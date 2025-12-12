//! DNS resolver module using hickory-resolver.
//!
//! This module provides a DNS resolver that:
//! - Resolves Kubernetes service and pod names to VIPs
//! - Forwards non-K8s queries to upstream DNS servers
//! - Uses interface-bound sockets to bypass TUN routing

use anyhow::Result;
use hickory_proto::op::{Message, ResponseCode};
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
use tracing::{debug, info, trace, warn};

use crate::dns::{build_formerr_response, DnsHandler, DnsQuery, K8sQueryType, PodDnsInfo};
use crate::k8s::K8sClient;
use crate::vip::{PodId, ServiceId, TargetId, VipManager};

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
            io::Error::other(format!(
                "Failed to bind to interface '{}': {} (may require root/CAP_NET_RAW)",
                interface_name, e
            ))
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
    vip_manager: VipManager,
    /// Kubernetes client for validating resources.
    k8s_client: Arc<K8sClient>,
}

impl DnsResolver {
    /// Creates a new DNS resolver with the given configuration.
    pub async fn new(
        config: DnsResolverConfig,
        dns_handler: Arc<DnsHandler>,
        vip_manager: VipManager,
        k8s_client: Arc<K8sClient>,
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
            k8s_client,
        })
    }

    /// Resolves a DNS query and returns the response message.
    ///
    /// If the query is for a K8s service or pod, validates the resource exists
    /// and returns a VIP. Otherwise, forwards to the upstream DNS server.
    pub async fn resolve(&self, dns_data: &[u8]) -> Result<Message> {
        // Parse the DNS query
        let query = match DnsQuery::parse(dns_data) {
            Ok(q) => q,
            Err(e) => {
                debug!("Failed to parse DNS query: {}", e);
                return self.forward_raw_query(dns_data).await;
            }
        };

        let query_names: Vec<_> = query.questions().iter().map(|q| q.name.clone()).collect();
        trace!("DNS query for: {:?}", query_names);

        // Parse the query to determine if it's a K8s service, pod, or external
        let target_id = match self.dns_handler.parse_k8s_query(&query) {
            K8sQueryType::Service { name, namespace } => {
                self.resolve_service(&name, &namespace).await
            }
            K8sQueryType::Pod(pod_info) => self.resolve_pod(pod_info).await,
            K8sQueryType::NotK8s => {
                trace!("Not intercepting DNS query for {:?}", query_names);
                return self.forward_query(&query, &query_names).await
            }
        };
        let Some(target_id)  = target_id else  {
                return Ok(query.build_error_response(ResponseCode::NXDomain));
        };

        // Get or allocate a VIP for this pod (only after validation)
        let vip = match self.vip_manager.get_or_allocate_vip_for_target(target_id.clone()).await {
            Ok(vip) => vip,
            Err(e) => {
                warn!("Failed to allocate VIP for target {:?}: {}", target_id, e);
                return Ok(query.build_error_response(ResponseCode::ServFail));
            }
        };

        info!("k8s DNS resolution: {:?} -> {}", target_id, vip);

        Ok(query.build_response(vip))
    }

    /// Resolves a service DNS query, validating it exists before allocating a VIP.
    async fn resolve_service(
        &self,
        service_name: &str,
        namespace: &str,
    ) -> Option<TargetId> {
        // Validate that the service exists in Kubernetes before allocating a VIP
        let service = ServiceId::new(service_name, namespace);
        if let Err(e) = self.k8s_client.get_service_endpoints(&service).await {
            info!(
                "Service {}.{} not found in K8s: {}",
                service_name, namespace, e
            );
            return None;
        }
        Some(TargetId::Service(service))

    }

    /// Resolves a pod DNS query, validating it exists before allocating a VIP.
    async fn resolve_pod(&self, pod_info: PodDnsInfo) -> Option<TargetId> {
        // Validate pod exists in Kubernetes and create PodId based on the pod info type
        let pod_id= match &pod_info {
            PodDnsInfo::Ip { ip, namespace } => {
                // Validate pod exists by IP before allocating VIP
                let ip_str = ip.to_string();
                if let Err(e) = self.k8s_client.get_pod_by_ip(&ip_str, namespace).await {
                    debug!("Pod with IP {} not found in {}: {}", ip, namespace, e);
                    return None;
                }
                let pod_name = ip_str.replace('.', "-");

                    PodId::new(&pod_name, namespace)
            }
            PodDnsInfo::StatefulSet {
                pod_name,
                service: _,
                namespace,
            } => {
                // Validate StatefulSet pod exists before allocating VIP
                if let Err(e) = self.k8s_client.get_pod_by_name(pod_name, namespace).await {
                    info!("Pod {} not found in {}: {}", pod_name, namespace, e);
                    return None;
                }

                    PodId::new(pod_name, namespace)
            }
            PodDnsInfo::Hostname {
                hostname,
                subdomain,
                namespace,
            } => {
                // Validate pod with hostname/subdomain exists before allocating VIP
                if let Err(e) = self
                    .k8s_client
                    .get_pod_by_hostname(hostname, subdomain, namespace)
                    .await
                {
                    info!(
                        "Pod with hostname {}.{} not found in {}: {}",
                        hostname, subdomain, namespace, e
                    );
                    return None;
                }
                let pod_name = format!("{}.{}", hostname, subdomain);

                    PodId::new(&pod_name, namespace)

            }
        };
       Some(TargetId::Pod(pod_id))

    }

    /// Forwards a parsed query to the upstream DNS server using hickory-resolver.
    async fn forward_query(&self, query: &DnsQuery, query_names: &[String]) -> Result<Message> {
        // Get the first question to forward
        let questions = query.questions();
        let question = match questions.first() {
            Some(q) => q,
            None => {
                trace!("No questions in query, returning empty response");
                return Ok(query.build_empty_response());
            }
        };

        trace!(
            "Forwarding {:?} query for {} to upstream",
            question.qtype, question.name
        );

        // Use hickory-resolver to resolve with the actual record type
        match self
            .upstream_resolver
            .lookup(&question.name, question.qtype)
            .await
        {
            Ok(lookup) => {
                trace!(
                    "Upstream resolved {:?} for {} with {} records",
                    query_names,
                    question.name,
                    lookup.records().len()
                );

                // Build response with all records from the lookup
                Ok(query.build_response_with_records(lookup.records()))
            }
            Err(e) => {
                // Determine appropriate DNS response code based on error type
                let rcode = if e.is_nx_domain() {
                    hickory_proto::op::ResponseCode::NXDomain
                } else if e.is_no_records_found() {
                    // Domain exists but no records of the requested type
                    hickory_proto::op::ResponseCode::NoError
                } else {
                    // For other errors (timeout, network issues, etc.), return SERVFAIL
                    hickory_proto::op::ResponseCode::ServFail
                };

                trace!(
                    "Upstream DNS resolution failed for {}: {} (returning {:?})",
                    question.name, e, rcode
                );

                if e.is_no_records_found() && !e.is_nx_domain() {
                    // Return empty response for "no records" (domain exists)
                    Ok(query.build_empty_response())
                } else {
                    Ok(query.build_error_response(rcode))
                }
            }
        }
    }

    /// Forwards a raw DNS query that couldn't be parsed.
    async fn forward_raw_query(&self, dns_data: &[u8]) -> Result<Message> {
        // For unparseable queries, return FORMERR (format error) response
        debug!("Cannot forward unparseable DNS query, returning FORMERR");
        Ok(build_formerr_response(dns_data))
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
    #[ignore = "requires Kubernetes cluster connection"]
    async fn test_resolver_creation() {
        // This test requires a running Kubernetes cluster to create a K8sClient
        // Run with: cargo test -- --ignored
        let config = DnsResolverConfig {
            upstream_dns: Ipv4Addr::new(8, 8, 8, 8),
            bind_interface: "en0".to_string(),
        };

        let dns_handler = Arc::new(DnsHandler::new(make_namespace_set(vec!["default"])));
        let vip_manager = VipManager::new(Ipv4Addr::new(198, 18, 0, 0));
        let k8s_client = Arc::new(
            K8sClient::new(None)
                .await
                .expect("Failed to create K8s client"),
        );

        let resolver = DnsResolver::new(config, dns_handler, vip_manager, k8s_client).await;
        assert!(resolver.is_ok());
    }
}
