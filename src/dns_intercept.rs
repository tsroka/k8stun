//! DNS interception module.
//!
//! This module handles intercepting DNS traffic by:
//! 1. Detecting the system's DNS server
//! 2. Routing DNS server traffic through the TUN device
//! 3. Forwarding non-K8s queries to the original DNS via the original interface

#![allow(dead_code)]

use anyhow::{anyhow, Context, Result};
use socket2::{Domain, Protocol, Socket, Type};
use std::net::{Ipv4Addr, SocketAddr};
use std::process::Command;
use std::time::Duration;
use tracing::{debug, info, warn};

#[cfg(target_os = "macos")]
use std::{ffi::CString, num::NonZeroU32};

/// Configuration for DNS interception.
#[derive(Debug, Clone)]
pub struct DnsInterceptConfig {
    /// The system's original DNS server that we'll intercept.
    pub system_dns: Ipv4Addr,
    /// The network interface name to bind to when forwarding DNS.
    /// This ensures forwarded queries bypass the TUN.
    pub bind_interface: String,
    /// Port for DNS (usually 53).
    pub dns_port: u16,
}

impl Default for DnsInterceptConfig {
    fn default() -> Self {
        Self {
            system_dns: Ipv4Addr::new(0, 0, 0, 0), // Will be detected
            bind_interface: String::new(),         // Will be detected
            dns_port: 53,
        }
    }
}

/// Manages DNS interception lifecycle.
pub struct DnsInterceptor {
    config: DnsInterceptConfig,
    original_route: Option<String>,
    tun_device_name: String,
}

impl DnsInterceptor {
    /// Creates a new DNS interceptor.
    ///
    /// Detects the system DNS server and the interface to bind to for forwarding.
    pub fn new(tun_device_name: String) -> Result<Self> {
        let system_dns = detect_system_dns()?;
        info!("Detected system DNS server: {}", system_dns);

        // Detect the interface to use for forwarding (bypasses TUN)
        let bind_interface = detect_default_interface_name()?;
        info!(
            "Will bind to interface '{}' for upstream DNS forwarding",
            bind_interface
        );

        let config = DnsInterceptConfig {
            system_dns,
            bind_interface,
            ..Default::default()
        };

        Ok(Self {
            config,
            original_route: None,
            tun_device_name,
        })
    }

    /// Enables DNS interception by routing DNS traffic through the TUN.
    pub fn enable(&mut self) -> Result<()> {
        let dns_ip = self.config.system_dns;

        // Don't intercept if system DNS is localhost or in our VIP range
        if dns_ip.is_loopback() || is_in_vip_range(dns_ip) {
            return Err(anyhow!(
                "Cannot intercept DNS server {} - it's localhost or in VIP range",
                dns_ip
            ));
        }

        info!(
            "Enabling DNS interception: {} -> TUN (forward via interface '{}')",
            dns_ip, self.config.bind_interface
        );

        // Save original route (if any) and add new route through TUN
        self.add_dns_route()?;

        Ok(())
    }

    /// Disables DNS interception and restores original routing.
    pub fn disable(&mut self) -> Result<()> {
        info!("Disabling DNS interception");
        self.remove_dns_route()?;
        Ok(())
    }

    /// Returns the system DNS server IP.
    pub fn system_dns(&self) -> Ipv4Addr {
        self.config.system_dns
    }

    /// Returns the interface name for upstream DNS forwarding.
    pub fn bind_interface(&self) -> &str {
        &self.config.bind_interface
    }

    #[cfg(target_os = "macos")]
    fn add_dns_route(&mut self) -> Result<()> {
        let dns_ip = self.config.system_dns.to_string();

        // Add host route for DNS server through TUN
        let output = Command::new("route")
            .args([
                "-n",
                "add",
                "-host",
                &dns_ip,
                "-interface",
                &self.tun_device_name,
            ])
            .output()
            .context("Failed to add DNS route")?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            if !stderr.contains("File exists") {
                warn!("Route command warning: {}", stderr);
            }
        }

        debug!("Added route for {} via {}", dns_ip, self.tun_device_name);
        self.original_route = Some(dns_ip);
        Ok(())
    }

    #[cfg(target_os = "linux")]
    fn add_dns_route(&mut self) -> Result<()> {
        let dns_ip = self.config.system_dns.to_string();

        let output = Command::new("ip")
            .args(["route", "add", &dns_ip, "dev", &self.tun_device_name])
            .output()
            .context("Failed to add DNS route")?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            if !stderr.contains("File exists") {
                warn!("Route command warning: {}", stderr);
            }
        }

        debug!("Added route for {} via {}", dns_ip, self.tun_device_name);
        self.original_route = Some(dns_ip);
        Ok(())
    }

    #[cfg(target_os = "macos")]
    fn remove_dns_route(&mut self) -> Result<()> {
        if let Some(ref dns_ip) = self.original_route {
            let _ = Command::new("route")
                .args(["-n", "delete", "-host", dns_ip])
                .output();
            debug!("Removed route for {}", dns_ip);
        }
        self.original_route = None;
        Ok(())
    }

    #[cfg(target_os = "linux")]
    fn remove_dns_route(&mut self) -> Result<()> {
        if let Some(ref dns_ip) = self.original_route {
            let _ = Command::new("ip").args(["route", "del", dns_ip]).output();
            debug!("Removed route for {}", dns_ip);
        }
        self.original_route = None;
        Ok(())
    }
}

impl Drop for DnsInterceptor {
    fn drop(&mut self) {
        if let Err(e) = self.disable() {
            warn!("Failed to disable DNS interception on drop: {}", e);
        }
    }
}

/// Detects the system's primary DNS server.
#[cfg(target_os = "macos")]
fn detect_system_dns() -> Result<Ipv4Addr> {
    // On macOS, use scutil --dns to get DNS configuration
    let output = Command::new("scutil")
        .args(["--dns"])
        .output()
        .context("Failed to run scutil --dns")?;

    let stdout = String::from_utf8_lossy(&output.stdout);

    // Parse output looking for "nameserver[0]" entries
    for line in stdout.lines() {
        let line = line.trim();
        if line.starts_with("nameserver[") || line.starts_with("nameserver :") {
            // Extract IP address
            if let Some(ip_str) = line.split_whitespace().last() {
                if let Ok(ip) = ip_str.parse::<Ipv4Addr>() {
                    // Skip localhost and link-local
                    if !ip.is_loopback() && !ip.is_link_local() {
                        return Ok(ip);
                    }
                }
            }
        }
    }

    // Fallback: try to read from /etc/resolv.conf
    detect_dns_from_resolv_conf()
}

#[cfg(target_os = "linux")]
fn detect_system_dns() -> Result<Ipv4Addr> {
    detect_dns_from_resolv_conf()
}

/// Parses /etc/resolv.conf to find DNS servers.
fn detect_dns_from_resolv_conf() -> Result<Ipv4Addr> {
    let content =
        std::fs::read_to_string("/etc/resolv.conf").context("Failed to read /etc/resolv.conf")?;

    for line in content.lines() {
        let line = line.trim();
        if line.starts_with("nameserver") {
            if let Some(ip_str) = line.split_whitespace().nth(1) {
                if let Ok(ip) = ip_str.parse::<Ipv4Addr>() {
                    if !ip.is_loopback() {
                        return Ok(ip);
                    }
                }
            }
        }
    }

    Err(anyhow!("No DNS server found in /etc/resolv.conf"))
}

/// Detects the name of the default network interface.
/// This interface can be used to bind sockets to bypass TUN routing.
fn detect_default_interface_name() -> Result<String> {
    let interface = netdev::get_default_interface()
        .map_err(|e| anyhow!("Failed to get default interface: {}", e))?;

    debug!(
        "Default interface: {} (IPv4s: {:?})",
        interface.name, interface.ipv4
    );

    Ok(interface.name.clone())
}

/// Checks if an IP is in the VIP range (198.18.0.0/16).
fn is_in_vip_range(ip: Ipv4Addr) -> bool {
    let octets = ip.octets();
    octets[0] == 198 && octets[1] == 18
}

/// Forwards a DNS query to an upstream DNS server and returns the response.
///
/// By binding to a specific network interface, this bypasses the TUN routing
/// and sends the query through the original network interface.
pub async fn forward_dns_query(
    query: &[u8],
    upstream_dns: Ipv4Addr,
    bind_interface: &str,
) -> Result<Vec<u8>> {
    // Create a UDP socket bound to the specified interface
    let socket = create_interface_bound_socket(bind_interface)?;

    // Convert socket2::Socket to tokio::net::UdpSocket
    socket.set_nonblocking(true)?;
    let std_socket: std::net::UdpSocket = socket.into();
    let socket = tokio::net::UdpSocket::from_std(std_socket)
        .context("Failed to convert to tokio UdpSocket")?;

    let upstream_addr = SocketAddr::new(upstream_dns.into(), 53);

    debug!(
        "Forwarding DNS query via interface '{}' to {}",
        bind_interface, upstream_addr
    );

    socket
        .send_to(query, upstream_addr)
        .await
        .context("Failed to send DNS query to upstream")?;

    // Set a timeout for the response
    let mut buf = vec![0u8; 512];

    let recv_future = socket.recv_from(&mut buf);
    let result = tokio::time::timeout(Duration::from_secs(5), recv_future).await;

    match result {
        Ok(Ok((len, _))) => {
            buf.truncate(len);
            Ok(buf)
        }
        Ok(Err(e)) => Err(anyhow!("DNS recv error: {}", e)),
        Err(_) => Err(anyhow!("DNS query timeout")),
    }
}

/// Creates a UDP socket bound to a specific network interface.
#[cfg(target_os = "linux")]
fn create_interface_bound_socket(interface_name: &str) -> Result<Socket> {
    let socket = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))
        .context("Failed to create UDP socket")?;

    // On Linux, use SO_BINDTODEVICE (requires CAP_NET_RAW or root)
    socket
        .bind_device(Some(interface_name.as_bytes()))
        .context(format!(
            "Failed to bind socket to interface '{}' (may require root/CAP_NET_RAW)",
            interface_name
        ))?;

    // Bind to any address on port 0 (ephemeral port)
    let bind_addr: SocketAddr = "0.0.0.0:0".parse().unwrap();
    socket
        .bind(&bind_addr.into())
        .context("Failed to bind socket to ephemeral port")?;

    Ok(socket)
}

/// Creates a UDP socket bound to a specific network interface.
#[cfg(target_os = "macos")]
fn create_interface_bound_socket(interface_name: &str) -> Result<Socket> {
    let socket = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))
        .context("Failed to create UDP socket")?;

    // Convert interface name to index
    let if_name =
        CString::new(interface_name).context("Invalid interface name (contains null byte)")?;

    let if_index = unsafe { libc::if_nametoindex(if_name.as_ptr()) };
    if if_index == 0 {
        return Err(anyhow!(
            "Interface '{}' not found (if_nametoindex returned 0)",
            interface_name
        ));
    }

    // On macOS, use IP_BOUND_IF via socket2's bind_device_by_index
    let if_index = NonZeroU32::new(if_index).ok_or_else(|| anyhow!("Interface index is zero"))?;

    socket
        .bind_device_by_index_v4(Some(if_index))
        .context(format!(
            "Failed to bind socket to interface '{}'",
            interface_name
        ))?;

    debug!(
        "Bound socket to interface '{}' (index {})",
        interface_name, if_index
    );

    // Bind to any address on port 0 (ephemeral port)
    let bind_addr: SocketAddr = "0.0.0.0:0".parse().unwrap();
    socket
        .bind(&bind_addr.into())
        .context("Failed to bind socket to ephemeral port")?;

    Ok(socket)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_in_vip_range() {
        assert!(is_in_vip_range(Ipv4Addr::new(198, 18, 0, 1)));
        assert!(is_in_vip_range(Ipv4Addr::new(198, 18, 255, 255)));
        assert!(!is_in_vip_range(Ipv4Addr::new(8, 8, 8, 8)));
        assert!(!is_in_vip_range(Ipv4Addr::new(192, 168, 1, 1)));
    }

    #[test]
    fn test_default_config() {
        let config = DnsInterceptConfig::default();
        assert_eq!(config.dns_port, 53);
        // system_dns and bind_ip are detected at runtime
    }
}
