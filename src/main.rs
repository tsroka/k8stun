//! k8stun - Kubernetes Userspace Network Tunnel
//!
//! A transparent network tunnel that connects your local machine directly to
//! a Kubernetes cluster, allowing you to access internal Kubernetes services
//! from your local browser or terminal as if you were inside the cluster.

mod dns;
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
use tracing::{error, info, warn};
use tracing_subscriber::{fmt, EnvFilter};

use dns::DnsHandler;
use dns_intercept::DnsInterceptor;
use dns_resolver::{DnsResolver, DnsResolverConfig};
use k8s::{K8sClient, PodEndpoint};
use pipe::pipe;
use stack::NetworkStack;
use std::time::Duration;
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

    /// Specific services to expose (format: service.namespace:port)
    #[arg(short, long)]
    services: Vec<String>,

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

    /// Intercept DNS traffic from the system's DNS server.
    /// When enabled, DNS queries are routed through the TUN device.
    /// K8s service queries are resolved to VIPs, others are forwarded to the original DNS.
    #[arg(long, default_value = "true")]
    intercept_dns: bool,

    /// Kubernetes context to use (from kubeconfig). If not specified, uses current context.
    #[arg(short = 'c', long)]
    context: Option<String>,

    /// Stale VIP timeout in seconds (VIPs without connections are removed after this time)
    #[arg(long, default_value = "600")]
    stale_vip_timeout: u64,
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
                    match vip_manager.get_or_allocate_vip(service_id.clone()).await {
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

    // Pre-allocate VIPs for explicitly specified services
    for service_spec in &args.services {
        // Support both "service.namespace" and "service.namespace:port" formats
        // Port is ignored for VIP allocation (same VIP for all ports)
        let service_part = service_spec
            .rsplit_once(':')
            .map(|(s, _)| s)
            .unwrap_or(service_spec);

        if let Some(service_id) = ServiceId::from_dns_name(service_part) {
            match vip_manager.get_or_allocate_vip(service_id.clone()).await {
                Ok(vip) => {
                    info!("Pre-allocated {} -> {:?}", vip, service_id);
                }
                Err(e) => {
                    warn!("Failed to pre-allocate VIP: {}", e);
                }
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

    // Set up DNS interception if enabled
    let mut dns_interceptor: Option<DnsInterceptor> = None;
    let dns_resolver: Option<Arc<DnsResolver>> = if args.intercept_dns {
        info!("Setting up DNS interception...");
        match DnsInterceptor::new(tun_name.clone()) {
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
                        Arc::clone(&dns_handler),
                        vip_manager.clone(),
                        Arc::clone(&k8s_client),
                    )
                    .await
                    {
                        Ok(resolver) => {
                            dns_interceptor = Some(interceptor);
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
    } else {
        None
    };

    info!("Initializing userspace network stack...");

    // Initialize network stack with optional DNS resolver
    let mut network_stack = NetworkStack::new(async_device, vip_manager.clone(), dns_resolver)
        .await
        .context("Failed to initialize network stack")?;

    info!("Network stack initialized");
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

    if dns_interceptor.is_some() {
        info!("");
        info!("DNS interception is ACTIVE. You can use service and pod names directly:");
        info!("  curl http://backend.default/");
        info!("  curl http://api.production:8080/");
        info!("");
        info!("Pod DNS patterns supported:");
        info!("  curl http://mysql-0.mysql.default/             # StatefulSet pod");
        info!("  curl http://172-17-0-3.default.pod/            # Pod by IP");
    } else {
        info!("");
        info!("DNS interception is OFF. Use --intercept-dns to enable.");
        info!("Without it, use the VIP addresses directly.");
    }

    info!("");
    info!("Press Ctrl+C to stop.");
    info!("");

    // Set up graceful shutdown
    let shutdown = tokio::signal::ctrl_c();
    tokio::pin!(shutdown);

    // Main connection handling loop
    loop {
        tokio::select! {
            // Handle new TCP connections
            Some(connection) = network_stack.accept() => {
                let target = connection.target;
                let stream = connection.stream;
                let vip = connection.vip;
                let port = connection.port;
                let k8s = Arc::clone(&k8s_client);
                let vip_mgr = vip_manager.clone();

                info!(
                    "New connection to {}.{}:{} from {}",
                    target.name(), target.namespace(), port, stream.peer_addr
                );

                // Spawn a task to handle the connection
                tokio::spawn(async move {
                    // Register the connection with VipManager to track it
                    // The guard will automatically unregister when dropped
                    let _active_conn = match vip_mgr.register_connection(vip).await {
                        Some(guard) => guard,
                        None => {
                            error!("Failed to register connection for VIP {}", vip);
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

                    let result = pipe(stream, k8s_stream).await;

                    // Update byte counters on the active connection before logging
                    let update_stats = |stats: &pipe::PipeStats| {
                        _active_conn.add_bytes_sent(stats.bytes_to_server.load(std::sync::atomic::Ordering::Relaxed));
                        _active_conn.add_bytes_received(stats.bytes_to_client.load(std::sync::atomic::Ordering::Relaxed));
                    };

                    match result {
                        pipe::PipeResult::Completed { stats } => {
                            update_stats(&stats);
                            info!(
                                "Connection completed: {} ({} bytes)",
                                label, stats.total_bytes()
                            );
                        }
                        pipe::PipeResult::ClientClosed { stats } => {
                            update_stats(&stats);
                            info!(
                                "Client closed: {} ({} bytes)",
                                label, stats.total_bytes()
                            );
                        }
                        pipe::PipeResult::ServerClosed { stats } => {
                            update_stats(&stats);
                            info!(
                                "Server closed: {} ({} bytes)",
                                label, stats.total_bytes()
                            );
                        }
                        pipe::PipeResult::Error { error, stats } => {
                            update_stats(&stats);
                            warn!(
                                "Connection error: {} - {} ({} bytes)",
                                label, error, stats.total_bytes()
                            );
                        }
                    }
                    // _active_conn is dropped here, automatically unregistering the connection
                });
            }

            // Handle shutdown signal
            _ = &mut shutdown => {
                info!("");
                info!("Shutting down...");
                break;
            }
        }
    }

    // Cleanup DNS interception
    if let Some(mut interceptor) = dns_interceptor {
        if let Err(e) = interceptor.disable() {
            warn!("Failed to disable DNS interception: {}", e);
        }
    }

    info!("k8stun stopped");
    Ok(())
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
