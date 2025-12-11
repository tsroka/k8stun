//! DNS resolver module using hickory-resolver.
//!
//! This module provides a DNS resolver that:
//! - Resolves Kubernetes service and pod names to VIPs
//! - Forwards non-K8s queries to upstream DNS servers
//! - Uses interface-bound sockets to bypass TUN routing

use anyhow::{Context, Result};
use hickory_proto::runtime::iocompat::AsyncIoTokioAsStd;
use hickory_proto::runtime::{RuntimeProvider, Spawn, TokioTime};
use hickory_proto::xfer::Protocol;
use hickory_proto::ProtoError;
use hickory_resolver::config::{NameServerConfig, ResolverConfig, ResolverOpts};
use hickory_resolver::name_server::GenericConnector;
use hickory_resolver::Resolver;
use socket2::{Domain, Protocol as SockProtocol, Socket, Type};
use std::future::Future;
use std::io;
use std::net::{Ipv4Addr, SocketAddr};
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::{TcpStream, UdpSocket};
use tokio::sync::Mutex;
use tokio::task::JoinSet;
use tracing::{debug, info, warn};

use crate::dns::{DnsHandler, DnsQuery, PodDnsInfo};
use crate::vip::{PodId, ServiceId, VipManager};

#[cfg(target_os = "macos")]
use std::{ffi::CString, num::NonZeroU32};

/// Configuration for the DNS resolver.
#[derive(Clone)]
pub struct DnsResolverConfig {
    /// The upstream DNS server to forward non-K8s queries to.
    pub upstream_dns: Ipv4Addr,
    /// The network interface to bind to (bypasses TUN).
    pub bind_interface: String,
}

/// A runtime provider that binds sockets to a specific network interface.
/// This ensures DNS queries bypass the TUN device and go through the original interface.
#[derive(Clone)]
pub struct InterfaceBoundRuntimeProvider {
    interface_name: Arc<String>,
    handle: InterfaceBoundHandle,
}

impl InterfaceBoundRuntimeProvider {
    /// Creates a new runtime provider bound to the specified interface.
    pub fn new(interface_name: String) -> Self {
        Self {
            interface_name: Arc::new(interface_name),
            handle: InterfaceBoundHandle::new(),
        }
    }
}

/// Handle for spawning background tasks.
#[derive(Clone)]
pub struct InterfaceBoundHandle {
    join_set: Arc<Mutex<JoinSet<Result<(), ProtoError>>>>,
}

impl InterfaceBoundHandle {
    fn new() -> Self {
        Self {
            join_set: Arc::new(Mutex::new(JoinSet::new())),
        }
    }
}

impl Spawn for InterfaceBoundHandle {
    fn spawn_bg<F>(&mut self, future: F)
    where
        F: Future<Output = Result<(), ProtoError>> + Send + 'static,
    {
        let join_set = self.join_set.clone();
        tokio::spawn(async move {
            let mut guard = join_set.lock().await;
            guard.spawn(future);
        });
    }
}

/// Binds a socket2 Socket to a specific network interface.
#[cfg(target_os = "linux")]
fn bind_socket_to_interface(socket: &Socket, interface_name: &str) -> io::Result<()> {
    socket
        .bind_device(Some(interface_name.as_bytes()))
        .map_err(|e| {
            io::Error::new(
                io::ErrorKind::Other,
                format!(
                    "Failed to bind to interface '{}': {} (may require root/CAP_NET_RAW)",
                    interface_name, e
                ),
            )
        })
}

/// Binds a socket2 Socket to a specific network interface.
#[cfg(target_os = "macos")]
fn bind_socket_to_interface(socket: &Socket, interface_name: &str) -> io::Result<()> {
    let if_name = CString::new(interface_name).map_err(|e| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("Invalid interface name: {}", e),
        )
    })?;

    let if_index = unsafe { libc::if_nametoindex(if_name.as_ptr()) };
    if if_index == 0 {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            format!("Interface '{}' not found", interface_name),
        ));
    }

    let if_index =
        NonZeroU32::new(if_index).ok_or_else(|| io::Error::other("Interface index is zero"))?;

    socket.bind_device_by_index_v4(Some(if_index)).map_err(|e| {
        io::Error::other(format!(
            "Failed to bind to interface '{}': {}",
            interface_name, e
        ))
    })
}

/// Creates a UDP socket bound to a specific network interface.
fn create_interface_bound_udp_socket(
    interface_name: &str,
    local_addr: SocketAddr,
) -> io::Result<std::net::UdpSocket> {
    let socket = Socket::new(Domain::IPV4, Type::DGRAM, Some(SockProtocol::UDP))?;

    bind_socket_to_interface(&socket, interface_name)?;

    socket.set_nonblocking(true)?;
    socket.bind(&local_addr.into())?;

    Ok(socket.into())
}

impl RuntimeProvider for InterfaceBoundRuntimeProvider {
    type Handle = InterfaceBoundHandle;
    type Timer = TokioTime;
    type Udp = UdpSocket;
    type Tcp = AsyncIoTokioAsStd<TcpStream>;

    fn create_handle(&self) -> Self::Handle {
        self.handle.clone()
    }

    fn connect_tcp(
        &self,
        server_addr: SocketAddr,
        _bind_addr: Option<SocketAddr>,
        timeout_duration: Option<Duration>,
    ) -> Pin<Box<dyn Send + Future<Output = io::Result<Self::Tcp>>>> {
        let interface_name = self.interface_name.clone();
        let timeout_duration = timeout_duration.unwrap_or(Duration::from_secs(5));

        Box::pin(async move {
            // Create socket2 socket, bind to interface, then connect
            let socket = Socket::new(Domain::IPV4, Type::STREAM, Some(SockProtocol::TCP))?;
            bind_socket_to_interface(&socket, &interface_name)?;
            socket.set_nonblocking(true)?;
            socket.set_nodelay(true)?;

            // Initiate non-blocking connect
            match socket.connect(&server_addr.into()) {
                Ok(()) => {}
                Err(e) if e.raw_os_error() == Some(libc::EINPROGRESS) => {}
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {}
                Err(e) => return Err(e),
            }

            // Convert to tokio TcpStream
            let std_stream: std::net::TcpStream = socket.into();
            let stream = TcpStream::from_std(std_stream)?;

            // Wait for connection to complete
            match tokio::time::timeout(timeout_duration, stream.writable()).await {
                Ok(Ok(())) => {
                    // Check for connection error
                    if let Some(e) = stream.take_error()? {
                        return Err(e);
                    }
                    Ok(AsyncIoTokioAsStd(stream))
                }
                Ok(Err(e)) => Err(e),
                Err(_) => Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    format!("TCP connect to {} timed out", server_addr),
                )),
            }
        })
    }

    fn bind_udp(
        &self,
        local_addr: SocketAddr,
        _server_addr: SocketAddr,
    ) -> Pin<Box<dyn Send + Future<Output = io::Result<Self::Udp>>>> {
        let interface_name = self.interface_name.clone();

        Box::pin(async move {
            let std_socket = create_interface_bound_udp_socket(&interface_name, local_addr)?;
            UdpSocket::from_std(std_socket)
        })
    }
}

/// Type alias for our custom resolver.
pub type InterfaceBoundResolver = Resolver<GenericConnector<InterfaceBoundRuntimeProvider>>;

/// DNS resolver that handles K8s service resolution and upstream forwarding.
pub struct DnsResolver {
    /// The hickory async resolver for upstream queries.
    upstream_resolver: InterfaceBoundResolver,
    /// Handler for K8s DNS logic.
    dns_handler: Arc<DnsHandler>,
    /// VIP manager for allocating virtual IPs.
    vip_manager: Arc<VipManager>,
}

impl DnsResolver {
    /// Creates a new DNS resolver with the given configuration.
    pub async fn new(
        config: DnsResolverConfig,
        dns_handler: Arc<DnsHandler>,
        vip_manager: Arc<VipManager>,
    ) -> Result<Self> {
        info!(
            "Creating DNS resolver with upstream {} via interface '{}'",
            config.upstream_dns, config.bind_interface
        );

        // Configure resolver to use the upstream DNS server
        let name_server = NameServerConfig::new(
            SocketAddr::new(config.upstream_dns.into(), 53),
            Protocol::Udp,
        );

        let resolver_config = ResolverConfig::from_parts(None, vec![], vec![name_server]);

        let mut resolver_opts = ResolverOpts::default();
        // Set reasonable timeouts
        resolver_opts.timeout = Duration::from_secs(5);
        resolver_opts.attempts = 2;

        // Create the interface-bound runtime provider
        let runtime_provider = InterfaceBoundRuntimeProvider::new(config.bind_interface.clone());
        let connector = GenericConnector::new(runtime_provider);

        let upstream_resolver = Resolver::builder_with_config(resolver_config, connector)
            .with_options(resolver_opts)
            .build();

        debug!(
            "DNS resolver created, bound to interface '{}'",
            config.bind_interface
        );

        Ok(Self {
            upstream_resolver,
            dns_handler,
            vip_manager,
        })
    }

    /// Resolves a DNS query and returns the response bytes.
    ///
    /// If the query is for a K8s service or pod, returns a VIP.
    /// Otherwise, forwards to the upstream DNS server.
    pub async fn resolve(&self, dns_data: &[u8]) -> Result<Option<Vec<u8>>> {
        if dns_data.is_empty() {
            return Ok(None);
        }

        // Parse the DNS query
        let query = match DnsQuery::parse(dns_data) {
            Ok(q) => q,
            Err(e) => {
                debug!("Failed to parse DNS query: {}", e);
                // If we can't parse it, try to forward anyway
                return self.forward_raw_query(dns_data).await;
            }
        };

        let query_names: Vec<_> = query.questions().iter().map(|q| q.name.clone()).collect();
        debug!("DNS query for: {:?}", query_names);

        // Check if we should intercept this query (K8s service or pod)
        if !self.dns_handler.should_intercept(&query) {
            debug!("Not intercepting DNS query for {:?}", query_names);
            return self.forward_query(&query, &query_names).await;
        }

        // Check if this is a pod query first
        if self.dns_handler.is_pod_query(&query) {
            return self.resolve_pod_query(&query, &query_names).await;
        }

        // Extract service info and resolve to VIP
        let (service_name, namespace) = match self.dns_handler.extract_service_info(&query) {
            Some(info) => info,
            None => {
                debug!("Could not extract service info from query");
                return self.forward_query(&query, &query_names).await;
            }
        };

        // Get or allocate a VIP for this service
        let service = ServiceId::new(&service_name, &namespace, 80); // Default port
        let vip = self
            .vip_manager
            .get_or_allocate_vip(service)
            .await
            .context("Failed to allocate VIP")?;

        info!("DNS: {}.{} -> {}", service_name, namespace, vip);

        // Build and return the response
        let response = query.build_response(vip);
        Ok(Some(response.to_vec()))
    }

    /// Resolves a pod DNS query and returns the response bytes.
    async fn resolve_pod_query(
        &self,
        query: &DnsQuery,
        query_names: &[String],
    ) -> Result<Option<Vec<u8>>> {
        let pod_info = match self.dns_handler.extract_pod_info(query) {
            Some(info) => info,
            None => {
                debug!("Could not extract pod info from query");
                return self.forward_query(query, query_names).await;
            }
        };

        // Create a PodId and allocate a VIP based on the pod info type
        let (pod_id, log_name) = match &pod_info {
            PodDnsInfo::Ip { ip, namespace } => {
                // For IP-based queries, use the IP as the pod name
                // The actual pod lookup will happen when the connection is made
                let pod_name = ip.to_string().replace('.', "-");
                (
                    PodId::new(&pod_name, namespace, 80),
                    format!("{}.{}.pod", ip, namespace),
                )
            }
            PodDnsInfo::StatefulSet {
                pod_name,
                service,
                namespace,
            } => (
                PodId::new(pod_name, namespace, 80),
                format!("{}.{}.{}", pod_name, service, namespace),
            ),
            PodDnsInfo::Hostname {
                hostname,
                subdomain,
                namespace,
            } => {
                // For hostname-based queries, combine hostname and subdomain as the pod identifier
                let pod_name = format!("{}.{}", hostname, subdomain);
                (
                    PodId::new(&pod_name, namespace, 80),
                    format!("{}.{}.{}", hostname, subdomain, namespace),
                )
            }
        };

        // Get or allocate a VIP for this pod
        let vip = self
            .vip_manager
            .get_or_allocate_vip_for_pod(pod_id)
            .await
            .context("Failed to allocate VIP for pod")?;

        info!("DNS (pod): {} -> {}", log_name, vip);

        // Build and return the response
        let response = query.build_response(vip);
        Ok(Some(response.to_vec()))
    }

    /// Forwards a parsed query to the upstream DNS server using hickory-resolver.
    async fn forward_query(
        &self,
        query: &DnsQuery,
        query_names: &[String],
    ) -> Result<Option<Vec<u8>>> {
        // Get the questions and find an A/AAAA record
        let questions = query.questions();
        let question = match questions.iter().find(|q| {
            q.qtype == hickory_proto::rr::RecordType::A
                || q.qtype == hickory_proto::rr::RecordType::AAAA
        }) {
            Some(q) => q,
            None => {
                debug!("No A/AAAA record in query, skipping");
                return Ok(None);
            }
        };

        debug!("Forwarding query for {} to upstream", question.name);

        // Use hickory-resolver to resolve
        match self.upstream_resolver.lookup_ip(&question.name).await {
            Ok(lookup) => {
                debug!("Upstream resolved {:?} for {}", query_names, question.name);

                // Build response with the first IPv4 address
                if let Some(ip) = lookup.iter().find_map(|addr| match addr {
                    std::net::IpAddr::V4(v4) => Some(v4),
                    _ => None,
                }) {
                    let response = query.build_response(ip);
                    return Ok(Some(response.to_vec()));
                }

                debug!("No IPv4 address in upstream response");
                Ok(None)
            }
            Err(e) => {
                warn!(
                    "Upstream DNS resolution failed for {}: {}",
                    question.name, e
                );
                Ok(None)
            }
        }
    }

    /// Forwards a raw DNS query that couldn't be parsed.
    async fn forward_raw_query(&self, _dns_data: &[u8]) -> Result<Option<Vec<u8>>> {
        // For unparseable queries, we can't use hickory-resolver's high-level API
        // Just return None and let the client retry
        debug!("Cannot forward unparseable DNS query");
        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use arc_swap::ArcSwap;
    use std::collections::HashSet;

    fn make_namespace_set(namespaces: Vec<&str>) -> crate::k8s::NamespaceSet {
        Arc::new(ArcSwap::from_pointee(
            namespaces
                .into_iter()
                .map(String::from)
                .collect::<HashSet<_>>(),
        ))
    }

    #[tokio::test]
    async fn test_resolver_creation() {
        let config = DnsResolverConfig {
            upstream_dns: Ipv4Addr::new(8, 8, 8, 8),
            bind_interface: "en0".to_string(),
        };

        let dns_handler = Arc::new(DnsHandler::new(make_namespace_set(vec!["default"])));
        let vip_manager = Arc::new(VipManager::new(Ipv4Addr::new(198, 18, 0, 0)));

        let resolver = DnsResolver::new(config, dns_handler, vip_manager).await;
        assert!(resolver.is_ok());
    }
}
