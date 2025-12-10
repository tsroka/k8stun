//! k8stun - Kubernetes Userspace Network Tunnel
//!
//! A transparent network tunnel that connects your local machine directly to
//! a Kubernetes cluster, allowing you to access internal Kubernetes services
//! from your local browser or terminal as if you were inside the cluster.

mod dns;
mod dns_intercept;
mod k8s;
mod pipe;
mod stack;
mod tun;
mod vip;

use anyhow::{Context, Result};
use clap::Parser;
use std::net::Ipv4Addr;
use std::sync::Arc;
use tracing::{error, info, warn, Level};
use tracing_subscriber::FmtSubscriber;

use dns::DnsHandler;
use dns_intercept::DnsInterceptor;
use k8s::K8sClient;
use pipe::pipe;
use stack::{DnsForwardConfig, NetworkStack};
use tun::{TunConfig, TunDevice};
use vip::{ServiceId, VipManager};

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

    /// Log level (trace, debug, info, warn, error)
    #[arg(short, long, default_value = "debug")]
    log_level: String,

    /// MTU for the TUN device
    #[arg(long, default_value = "1500")]
    mtu: u16,

    /// Idle connection timeout in seconds (0 = no timeout)
    #[arg(long, default_value = "300")]
    idle_timeout: u64,

    /// Intercept DNS traffic from the system's DNS server.
    /// When enabled, DNS queries are routed through the TUN device.
    /// K8s service queries are resolved to VIPs, others are forwarded to the original DNS.
    #[arg(long)]
    intercept_dns: bool,

    /// Kubernetes context to use (from kubeconfig). If not specified, uses current context.
    #[arg(short = 'c', long)]
    context: Option<String>,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    // Initialize logging
    let log_level = match args.log_level.to_lowercase().as_str() {
        "trace" => Level::TRACE,
        "debug" => Level::DEBUG,
        "info" => Level::INFO,
        "warn" => Level::WARN,
        "error" => Level::ERROR,
        _ => Level::INFO,
    };

    FmtSubscriber::builder()
        .with_max_level(log_level)
        .with_target(false)
        .with_thread_ids(false)
        .with_file(false)
        .with_line_number(false)
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

    // Initialize VIP manager
    let vip_manager = Arc::new(VipManager::new(args.vip_base));

    // Initialize DNS handler with dynamic namespace set
    let dns_handler = Arc::new(DnsHandler::new(namespace_set));

    // Auto-discover services if enabled
    if args.auto_discover {
        info!("Discovering services in target namespaces...");
        match k8s_client.list_services(&namespaces).await {
            Ok(services) => {
                for svc in services {
                    for port in svc.ports {
                        let service_id = ServiceId::new(&svc.name, &svc.namespace, port);
                        match vip_manager.get_or_allocate_vip(service_id.clone()).await {
                            Ok(vip) => {
                                info!(
                                    "  {} -> {}.{}:{} (port {})",
                                    vip, svc.name, svc.namespace, port, port
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
        if let Some((service_part, port_str)) = service_spec.rsplit_once(':') {
            let port: u16 = port_str.parse().unwrap_or(80);
            if let Some(service_id) = ServiceId::from_dns_name(service_part, port) {
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
    let dns_forward_config: Option<DnsForwardConfig> = if args.intercept_dns {
        info!("Setting up DNS interception...");
        match DnsInterceptor::new(tun_name.clone()) {
            Ok(mut interceptor) => match interceptor.enable() {
                Ok(()) => {
                    info!(
                        "DNS interception enabled: {} -> TUN (forward via interface '{}')",
                        interceptor.system_dns(),
                        interceptor.bind_interface()
                    );
                    let config = DnsForwardConfig {
                        system_dns: interceptor.system_dns(),
                        bind_interface: interceptor.bind_interface().to_string(),
                    };
                    dns_interceptor = Some(interceptor);
                    Some(config)
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

    // Initialize network stack with optional DNS forwarding
    let mut network_stack = NetworkStack::with_dns_forward(
        async_device,
        Arc::clone(&vip_manager),
        Arc::clone(&dns_handler),
        dns_forward_config,
    )
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
        info!("  curl http://{}:{}/", vip, service.port);
        info!("    -> {}.{}", service.name, service.namespace);
    }

    if mappings.is_empty() {
        info!("  (services will be resolved via DNS on first access)");
    }

    if dns_interceptor.is_some() {
        info!("");
        info!("DNS interception is ACTIVE. You can use service names directly:");
        info!("  curl http://backend.default/");
        info!("  curl http://api.production:8080/");
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
                let service = connection.service;
                let stream = connection.stream;
                let k8s = Arc::clone(&k8s_client);

                info!(
                    "New connection to {}.{}:{} from {}",
                    service.name, service.namespace, service.port, stream.peer_addr
                );

                // Spawn a task to handle the connection
                tokio::spawn(async move {
                    // Get a pod endpoint for this service
                    let endpoint = match k8s.get_next_endpoint(&service).await {
                        Ok(ep) => ep,
                        Err(e) => {
                            error!(
                                "Failed to get endpoint for {}.{}: {}",
                                service.name, service.namespace, e
                            );
                            return;
                        }
                    };

                    info!(
                        "Forwarding to pod {}/{} port {}",
                        endpoint.namespace, endpoint.name, endpoint.port
                    );

                    // Establish port-forward to the pod
                    let k8s_stream = match k8s.port_forward(&endpoint).await {
                        Ok(s) => s,
                        Err(e) => {
                            error!("Failed to establish port-forward: {}", e);
                            return;
                        }
                    };

                    // Pipe data between the streams
                    let label = format!(
                        "{}.{}:{} -> {}/{}:{}",
                        service.name, service.namespace, service.port,
                        endpoint.namespace, endpoint.name, endpoint.port
                    );

                    let result = pipe(stream, k8s_stream).await;

                    match result {
                        pipe::PipeResult::Completed { stats } => {
                            info!(
                                "Connection completed: {} ({} bytes)",
                                label, stats.total_bytes()
                            );
                        }
                        pipe::PipeResult::ClientClosed { stats } => {
                            info!(
                                "Client closed: {} ({} bytes)",
                                label, stats.total_bytes()
                            );
                        }
                        pipe::PipeResult::ServerClosed { stats } => {
                            info!(
                                "Server closed: {} ({} bytes)",
                                label, stats.total_bytes()
                            );
                        }
                        pipe::PipeResult::Error { error, stats } => {
                            warn!(
                                "Connection error: {} - {} ({} bytes)",
                                label, error, stats.total_bytes()
                            );
                        }
                    }
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
