//! k8stun - Kubernetes Userspace Network Tunnel
//!
//! A transparent network tunnel that connects your local machine directly to
//! a Kubernetes cluster, allowing you to access internal Kubernetes services
//! from your local browser or terminal as if you were inside the cluster.

mod api;
mod dns;
#[cfg(target_os = "macos")]
mod dns_forward_macos;
mod dns_intercept;
mod dns_resolver;
mod k8s;
mod pipe;
mod stack;
mod tun;
mod vip;

use anyhow::{Context, Result};
use clap::Parser;
use std::net::Ipv4Addr;
use std::sync::Arc;
use tracing::{debug, error, info, warn};
use tracing_subscriber::{fmt, EnvFilter};

use crate::dns::build_servfail_response;
use crate::stack::{AcceptedConnection, UdpPacket};
use dns::DnsHandler;
#[cfg(target_os = "macos")]
use dns_forward_macos::DnsForwarder;
use dns_intercept::{detect_default_interface_name, detect_system_dns, DnsInterceptor, DnsMode};
use dns_resolver::{DnsResolver, DnsResolverConfig};
use futures::stream::FuturesUnordered;
use futures::StreamExt;
use k8s::{K8sClient, PodEndpoint};
use pipe::pipe;
use stack::NetworkStack;
use std::time::Duration;
use tokio::select;
use tokio::signal::unix::{signal, SignalKind};
use tokio::sync::mpsc::{Receiver, Sender};
use tokio::sync::Notify;
use tun::{TunConfig, TunDevice};
use vip::{PodId, ServiceId, TargetId, VipManager, VipManagerConfig};

/// Kubernetes Userspace Network Tunnel
///
/// Creates a transparent network tunnel to access Kubernetes services
/// from your local machine without modifying /etc/hosts.
#[derive(Parser, Debug)]
#[command(name = "k8stun")]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Kubernetes namespaces to expose (comma-separated)
    #[arg(short, long, default_value = "default")]
    namespaces: String,

    /// Virtual IP range base (e.g., 198.18.0.0)
    #[arg(long, default_value = "198.18.0.0")]
    vip_base: Ipv4Addr,

    /// Pre-allocate VIPs for all discovered services
    #[arg(long, default_value = "true")]
    auto_discover: bool,

    /// Log level for k8stun (trace, debug, info, warn, error)
    #[arg(short, long, default_value = "info")]
    log_level: String,

    /// Log level for libraries (trace, debug, info, warn, error)
    #[arg(long, default_value = "info")]
    lib_log_level: String,

    /// Show source file and line number in log messages
    #[arg(long, default_value = "false")]
    log_source: bool,

    /// MTU for the TUN device
    #[arg(long, default_value = "1500")]
    mtu: u16,

    /// Idle connection timeout in seconds (0 = no timeout)
    #[arg(long, default_value = "300")]
    idle_timeout: u64,

    /// DNS interception mode:
    /// - disabled: No DNS interception
    /// - tun_route: Route DNS traffic through TUN device (works on all platforms)
    /// - forward: Change system DNS settings to use our DNS server (macOS only)
    #[arg(long, default_value = "tun_route", value_enum)]
    dns_mode: dns_intercept::DnsMode,

    /// Kubernetes context to use (from kubeconfig). If not specified, uses current context.
    #[arg(short = 'c', long)]
    context: Option<String>,

    /// Stale VIP timeout in seconds (VIPs without connections are removed after this time)
    #[arg(long, default_value = "600")]
    stale_vip_timeout: u64,

    /// Port for the HTTP API server (0 to disable)
    #[arg(long, default_value = "0")]
    http: u16,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    // Initialize logging with separate levels for app and libraries
    let app_level = args.log_level.to_lowercase();
    let lib_level = args.lib_log_level.to_lowercase();

    // Build filter: k8stun at app_level, everything else at lib_level
    let filter = EnvFilter::new(format!("{lib_level},k8stun={app_level}"));

    fmt::Subscriber::builder()
        .with_env_filter(filter)
        .with_target(false)
        .with_thread_ids(false)
        .with_file(args.log_source)
        .with_line_number(args.log_source)
        .compact()
        .init();

    info!("Starting k8stun - Kubernetes Userspace Network Tunnel");

    // Parse namespaces
    let namespaces: Vec<String> = args
        .namespaces
        .split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();

    info!("Target namespaces: {:?}", namespaces);

    // Initialize Kubernetes client
    info!("Connecting to Kubernetes cluster...");
    let k8s_client = Arc::new(
        K8sClient::new(args.context.as_deref())
            .await
            .context("Failed to connect to Kubernetes. Check your kubeconfig.")?,
    );

    // Start namespace watcher to maintain up-to-date list of all namespaces
    info!("Starting namespace watcher...");
    let namespace_watcher = k8s_client.namespace_watcher();
    namespace_watcher.start();
    let namespace_set = namespace_watcher.namespace_set();

    // Initialize VIP manager with stale timeout configuration
    let vip_manager = VipManager::with_config(VipManagerConfig {
        base_ip: args.vip_base,
        stale_timeout: Duration::from_secs(args.stale_vip_timeout),
        cleanup_interval: Duration::from_secs(60),
    });

    // Initialize DNS handler with dynamic namespace set
    let dns_handler = Arc::new(DnsHandler::new(namespace_set));

    // Auto-discover services if enabled
    if args.auto_discover {
        info!("Discovering services in target namespaces...");
        match k8s_client.list_services(&namespaces).await {
            Ok(services) => {
                for svc in services {
                    let service_id = ServiceId::new(&svc.name, &svc.namespace);
                    match vip_manager
                        .get_or_allocate_vip_for_target(TargetId::Service(service_id.clone()))
                        .await
                    {
                        Ok(vip) => {
                            info!(
                                "  {} -> {}.{} (ports: {:?})",
                                vip, svc.name, svc.namespace, svc.ports
                            );
                        }
                        Err(e) => {
                            warn!(
                                "Failed to allocate VIP for {}.{}: {}",
                                svc.name, svc.namespace, e
                            );
                        }
                    }
                }
            }
            Err(e) => {
                warn!(
                    "Failed to discover services: {}. Will allocate VIPs on-demand.",
                    e
                );
            }
        }
    }

    // Create TUN device
    info!("Creating TUN device...");
    let tun_config = TunConfig {
        address: Ipv4Addr::new(args.vip_base.octets()[0], args.vip_base.octets()[1], 0, 1),
        route_cidr: format!("{}/16", args.vip_base),
        mtu: args.mtu,
        ..Default::default()
    };

    let tun_device = TunDevice::create(tun_config)
        .await
        .context("Failed to create TUN device. Are you running with sudo?")?;

    let tun_name = tun_device.name();
    info!("TUN device created: {}", tun_name);

    // Extract the async device for the network stack
    let async_device = tun_device
        .into_async_device()
        .context("Failed to extract async device from TUN")?;


    // Set up DNS based on mode
    let mut dns_interceptor: Option<DnsInterceptor> = None;
    #[cfg(target_os = "macos")]
    let mut dns_forwarder: Option<DnsForwarder> = None;
    let dns_resolver: Option<Arc<DnsResolver>> = match args.dns_mode {
        DnsMode::Disabled => {
            info!("DNS interception is disabled");
            None
        }
        DnsMode::TunRoute => {
            info!("Setting up DNS interception (tun_route mode)...");
            setup_dns_tun_route(
                tun_name.clone(),
                &dns_handler,
                &vip_manager,
                &k8s_client,
                &mut dns_interceptor,
            )
            .await
        }
        #[cfg(target_os = "macos")]
        DnsMode::Forward => {

            {
                info!("Setting up DNS forwarding (forward mode)...");
                // TUN interface IP address (used for DNS server)
                let tun_ip = Ipv4Addr::new(args.vip_base.octets()[0], args.vip_base.octets()[1], 0, 1);

                setup_dns_forward(
                    tun_ip,
                    tun_name.clone(),
                    &dns_handler,
                    &vip_manager,
                    &k8s_client,
                    &mut dns_forwarder,
                )
                .await
            }
            #[cfg(not(target_os = "macos"))]
            {
                warn!(
                    "DNS forward mode is only supported on macOS. Falling back to tun_route mode."
                );
                setup_dns_tun_route(
                    tun_name.clone(),
                    &dns_handler,
                    &vip_manager,
                    &k8s_client,
                    &mut dns_interceptor,
                )
                .await
            }
        }
    };

    info!("Initializing userspace network stack...");
    // Initialize network stack with optional DNS resolver
    let network_stack = NetworkStack::new(async_device)
        .await
        .context("Failed to initialize network stack")?;

    info!("Network stack initialized");

    // Start API server if enabled
    if args.http > 0 {
        let api_vip_manager = vip_manager.clone();
        let http_port = args.http;
        tokio::spawn(async move {
            if let Err(e) = api::start_server(http_port, api_vip_manager).await {
                error!("API server error: {}", e);
            }
        });
    }

    info!("");
    info!("===========================================");
    info!("k8stun is ready!");
    info!("===========================================");
    info!("");
    info!("You can now access Kubernetes services:");

    // Show allocated VIPs
    let mappings = vip_manager.get_all_mappings().await;
    for (vip, service) in &mappings {
        info!("  {} -> {}.{}", vip, service.name, service.namespace);
    }

    if mappings.is_empty() {
        info!("  (services will be resolved via DNS on first access)");
    }

    let dns_active = dns_resolver.is_some();
    if dns_active {
        info!("");
        info!(
            "DNS interception is ACTIVE ({} mode). You can use service and pod names directly:",
            args.dns_mode
        );
        info!("  curl http://backend.default/");
        info!("  curl http://api.production:8080/");
        info!("");
        info!("Pod DNS patterns supported:");
        info!("  curl http://mysql-0.mysql.default/             # StatefulSet pod");
        info!("  curl http://172-17-0-3.default.pod/            # Pod by IP");
    } else {
        info!("");
        info!("DNS interception is OFF. Use --dns-mode=tun_route to enable.");
        info!("Without it, use the VIP addresses directly.");
    }

    if args.http > 0 {
        info!("");
        info!("API server available at:");
        info!(
            "  GET  http://localhost:{}/vips    - Current VIP mappings",
            args.http
        );
        info!(
            "  GET  http://localhost:{}/events  - Real-time updates (SSE)",
            args.http
        );
    }

    info!("");
    info!("Press Ctrl+C to stop.");
    info!("");

    let shutdown_notify = Arc::new(Notify::new());

    let (tcp, udp_rx, udp_tx) = network_stack.split();
    let components = FuturesUnordered::new();

    let tcp_shutdown = shutdown_notify.clone();
    let tcp_loop_handle = tokio::spawn(async move {
        tcp_loop(k8s_client, vip_manager, tcp, tcp_shutdown).await;
        info!("TCP loop stopped");
    });
    components.push(tcp_loop_handle);
    let udp_shutdown = shutdown_notify.clone();

    let udp_loop_handle = tokio::spawn(async move {
        udp_loop(udp_tx, udp_rx, dns_resolver, udp_shutdown).await;
        info!("UDP loop stopped");
    });
    components.push(udp_loop_handle);

    let mut sig_int = signal(SignalKind::interrupt()).unwrap();
    let mut sig_term = signal(SignalKind::terminate()).unwrap();

    select! {
        _ = sig_int.recv() => info!("Received SIGINT (Ctrl+C)"),
        _ = sig_term.recv() => info!("Received SIGTERM"),
    }
    shutdown_notify.notify_waiters();
    info!("Shutting down...");
    let _res: Vec<_> = components.collect().await;

    // Cleanup DNS interception
    if let Some(mut interceptor) = dns_interceptor {
        if let Err(e) = interceptor.disable() {
            warn!("Failed to disable DNS interception: {}", e);
        }
    }

    // Cleanup DNS forwarder (macOS forward mode)
    #[cfg(target_os = "macos")]
    if let Some(mut forwarder) = dns_forwarder {
        if let Err(e) = forwarder.disable() {
            warn!("Failed to disable DNS forwarder: {}", e);
        }
    }

    info!("k8stun stopped");
    Ok(())
}

/// Sets up DNS in TunRoute mode (routes DNS traffic through TUN).
async fn setup_dns_tun_route(
    tun_name: String,
    dns_handler: &Arc<DnsHandler>,
    vip_manager: &VipManager,
    k8s_client: &Arc<K8sClient>,
    dns_interceptor: &mut Option<DnsInterceptor>,
) -> Option<Arc<DnsResolver>> {
    match DnsInterceptor::new(tun_name) {
        Ok(mut interceptor) => match interceptor.enable() {
            Ok(()) => {
                info!(
                    "DNS interception enabled: {} -> TUN (forward via interface '{}')",
                    interceptor.system_dns(),
                    interceptor.bind_interface()
                );

                // Create the DNS resolver with upstream configuration
                let resolver_config = DnsResolverConfig {
                    upstream_dns: interceptor.system_dns(),
                    bind_interface: interceptor.bind_interface().to_string(),
                };

                match DnsResolver::new(
                    resolver_config,
                    Arc::clone(dns_handler),
                    vip_manager.clone(),
                    Arc::clone(k8s_client),
                )
                .await
                {
                    Ok(resolver) => {
                        *dns_interceptor = Some(interceptor);
                        Some(Arc::new(resolver))
                    }
                    Err(e) => {
                        warn!(
                            "Failed to create DNS resolver: {}. Continuing without it.",
                            e
                        );
                        None
                    }
                }
            }
            Err(e) => {
                warn!(
                    "Failed to enable DNS interception: {}. Continuing without it.",
                    e
                );
                None
            }
        },
        Err(e) => {
            warn!(
                "Failed to set up DNS interceptor: {}. Continuing without it.",
                e
            );
            None
        }
    }
}

/// Sets up DNS in Forward mode (changes system DNS settings to point to our server).
#[cfg(target_os = "macos")]
/// DNS port - always use standard port 53
const DNS_PORT: u16 = 53;

#[cfg(target_os = "macos")]
async fn setup_dns_forward(
    tun_ip: Ipv4Addr,
    tun_name: String,
    dns_handler: &Arc<DnsHandler>,
    vip_manager: &VipManager,
    k8s_client: &Arc<K8sClient>,
    dns_forwarder: &mut Option<DnsForwarder>,
) -> Option<Arc<DnsResolver>> {
    // Detect system DNS and interface for upstream forwarding
    let system_dns = match detect_system_dns() {
        Ok(dns) => {
            info!("Detected system DNS server: {}", dns);
            dns
        }
        Err(e) => {
            warn!(
                "Failed to detect system DNS: {}. Continuing without DNS.",
                e
            );
            return None;
        }
    };

    let bind_interface = match detect_default_interface_name() {
        Ok(iface) => {
            info!(
                "Will bind to interface '{}' for upstream DNS forwarding",
                iface
            );
            iface
        }
        Err(e) => {
            warn!(
                "Failed to detect default interface: {}. Continuing without DNS.",
                e
            );
            return None;
        }
    };

    // Create the DNS resolver
    let resolver_config = DnsResolverConfig {
        upstream_dns: system_dns,
        bind_interface,
    };

    let resolver = match DnsResolver::new(
        resolver_config,
        Arc::clone(dns_handler),
        vip_manager.clone(),
        Arc::clone(k8s_client),
    )
    .await
    {
        Ok(r) => Arc::new(r),
        Err(e) => {
            warn!(
                "Failed to create DNS resolver: {}. Continuing without it.",
                e
            );
            return None;
        }
    };

    // Create and enable the DNS forwarder
    match DnsForwarder::new(tun_ip, DNS_PORT, tun_name) {
        Ok(mut forwarder) => match forwarder.enable() {
            Ok(()) => {
                info!(
                    "DNS forward mode enabled: system DNS -> {}:{}",
                    tun_ip, DNS_PORT
                );
                *dns_forwarder = Some(forwarder);
                Some(resolver)
            }
            Err(e) => {
                warn!(
                    "Failed to enable DNS forwarder: {}. Continuing without it.",
                    e
                );
                None
            }
        },
        Err(e) => {
            warn!(
                "Failed to create DNS forwarder: {}. Continuing without it.",
                e
            );
            None
        }
    }
}

async fn dns_responder(
    udp_packet: UdpPacket,
    dns_resolver: &DnsResolver,
    udp_tx: &mut Sender<UdpPacket>,
) -> Result<()> {
    let resp = match dns_resolver.resolve(&udp_packet.payload).await {
        Ok(response) => response.to_vec(),
        Err(e) => {
            debug!("DNS handling error: {}", e);
            // Send SERVFAIL response so client doesn't hang
            let response = build_servfail_response(&udp_packet.payload);
            response.to_vec()
        }
    };

    match resp {
        Ok(payload) => {
            udp_tx
                .send(UdpPacket {
                    src_addr: udp_packet.dst_addr,
                    dst_addr: udp_packet.src_addr,
                    payload,
                })
                .await?;
            Ok(())
        }
        Err(e) => {
            warn!("Failed to serialize DNS response: {}", e);
            Ok(())
        }
    }
}

async fn udp_loop(
    mut udp_rx: Receiver<UdpPacket>,
    mut udp_tx: Sender<UdpPacket>,
    dns_resolver: Option<Arc<DnsResolver>>,
    shutdown: Arc<Notify>,
) {
    loop {
        tokio::select! {
            // Handle new TCP connections
            Some(udp_packet) = udp_rx.recv() => {

                if udp_packet.dst_addr.port() == 53 {
                    if let Some(ref dns_resolver) = dns_resolver {
                     let res = dns_responder(udp_packet, dns_resolver, &mut udp_tx).await;
                            if let Err(e) = res {
                                error!("Failed to respond to DNS: {}", e);
                                break;
                            }
                    }

                }
            }
            _ = shutdown.notified() => {
                break;
            }
        }
    }
    info!("Shutting down udp loop...");
}
async fn tcp_loop(
    k8s_client: Arc<K8sClient>,
    vip_manager: VipManager,
    mut tcp: Receiver<AcceptedConnection>,
    shutdown: Arc<Notify>,
) {
    // Main connection handling loop
    loop {
        tokio::select! {
            // Handle new TCP connections
            Some(connection) = tcp.recv() => {

                let stream = connection.stream;
                let dst_ip = connection.dst_ip;
                let port = connection.dst_port;
                let src_addr = stream.local_addr;
                let k8s = Arc::clone(&k8s_client);
                let vip_mgr = vip_manager.clone();

                if !vip_manager.is_vip(dst_ip) {
                    debug!("Destination {} is not a VIP, refusing connection", dst_ip);
                    // lwip's TcpStream sends RST on drop if not closed, so just drop it
                    drop(stream);
                    continue;
                }
                       // Look up the target (service or pod)
                let target = match vip_manager.lookup_target(dst_ip).await {
                    Some(target) => target,
                    None => {
                        warn!("No target found for VIP {}, refusing connection", dst_ip);
                        // lwip's TcpStream sends RST on drop if not closed, so just drop it
                        drop(stream);
                        continue;
                    }
                };
                info!(
                    "New connection to {}.{}:{} from {}",
                    target.name(), target.namespace(), port, stream.peer_addr
                );

                // Spawn a task to handle the connection
                tokio::spawn(async move {

                    // Register the connection with VipManager to track it
                    // The guard will automatically unregister when dropped
                    let active_conn = match vip_mgr.register_connection(dst_ip, src_addr, port).await {
                        Some(guard) => guard,
                        None => {
                            error!("Failed to register connection for VIP {}", dst_ip);
                            return;
                        }
                    };

                    // Get a pod endpoint based on target type
                    let (endpoint, label) = match &target {
                        TargetId::Service(service) => {
                            // For services, use endpoint discovery with load balancing
                            match k8s.get_next_endpoint(service).await {
                                Ok(ep) => {
                                    let label = format!(
                                        "{}.{}:{} -> {}/{}:{}",
                                        service.name, service.namespace, port,
                                        ep.namespace, ep.name, port
                                    );
                                    (ep, label)
                                }
                                Err(e) => {
                                    error!(
                                        "Failed to get endpoint for {}.{}: {}",
                                        service.name, service.namespace, e
                                    );
                                    return;
                                }
                            }
                        }
                        TargetId::Pod(pod) => {
                            // For pods, connect directly
                            match get_pod_endpoint(&k8s, pod).await {
                                Ok(ep) => {
                                    let label = format!(
                                        "pod:{}.{}:{} -> {}/{}:{}",
                                        pod.name, pod.namespace, port,
                                        ep.namespace, ep.name, port
                                    );
                                    (ep, label)
                                }
                                Err(e) => {
                                    error!(
                                        "Failed to get pod endpoint for {}.{}: {}",
                                        pod.name, pod.namespace, e
                                    );
                                    return;
                                }
                            }
                        }
                    };

                    info!(
                        "Forwarding to pod {}/{} port {}",
                        endpoint.namespace, endpoint.name, port
                    );

                    // Establish port-forward to the pod
                    let k8s_stream = match k8s.port_forward(&endpoint, port).await {
                        Ok(s) => s,
                        Err(e) => {
                            error!("Failed to establish port-forward: {}", e);
                            return;
                        }
                    };

                    let result = pipe(active_conn, stream, k8s_stream).await;

                    match result {
                        Ok((tx_bytes, rx_bytes)) => {
                            info!(
                                "Connection completed: {} (tx: {} bytes, rx: {} bytes)",
                                label, tx_bytes, rx_bytes
                            );
                        }
                       Err(err) => {
                            info!(
                                "Connection error: {} - {}",
                                label, err
                            );
                        }
                    }
                    // _active_conn is dropped here, automatically unregistering the connection
                });
            }

            // Handle shutdown signal
            _ = shutdown.notified() => {

                break;
            }
        }
    }
    info!("Shutting down tcp loop...");
}

/// Gets a pod endpoint based on the PodId.
///
/// The pod name in PodId can be:
/// - An actual pod name (for StatefulSet pods like "mysql-0")
/// - A dashed IP address (for IP-based DNS like "172-17-0-3")
/// - A hostname.subdomain combination (for hostname-based DNS)
async fn get_pod_endpoint(k8s: &K8sClient, pod: &PodId) -> anyhow::Result<PodEndpoint> {
    // Check if the pod name looks like a dashed IP address (e.g., "172-17-0-3")
    if is_dashed_ip(&pod.name) {
        // Convert dashed IP back to dotted format
        let ip = pod.name.replace('-', ".");
        return k8s.get_pod_by_ip(&ip, &pod.namespace).await;
    }

    // Check if the pod name contains a dot (hostname.subdomain format)
    if let Some((hostname, subdomain)) = pod.name.split_once('.') {
        // Try to find by hostname and subdomain first
        match k8s
            .get_pod_by_hostname(hostname, subdomain, &pod.namespace)
            .await
        {
            Ok(ep) => return Ok(ep),
            Err(_) => {
                // If not found, try by name (the pod might just have a dotted name)
            }
        }
    }

    // Otherwise, look up by pod name directly
    k8s.get_pod_by_name(&pod.name, &pod.namespace).await
}

/// Checks if a string looks like a dashed IP address (e.g., "172-17-0-3").
fn is_dashed_ip(s: &str) -> bool {
    let parts: Vec<&str> = s.split('-').collect();
    if parts.len() != 4 {
        return false;
    }
    parts.iter().all(|p| p.parse::<u8>().is_ok())
}
