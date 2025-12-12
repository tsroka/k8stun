//! DNS interception module.
//!
//! This module handles intercepting DNS traffic by:
//! 1. Detecting the system's DNS server
//! 2. Routing DNS server traffic through the TUN device



use anyhow::{anyhow, Context, Result};
use std::net::Ipv4Addr;
use std::process::Command;
use tracing::{debug, info, warn};

/// Configuration for DNS interception.
#[derive(Debug, Clone)]
pub struct DnsInterceptConfig {
    /// The system's original DNS server that we'll intercept.
    pub system_dns: Ipv4Addr,
    /// The network interface name to bind to when forwarding DNS.
    /// This ensures forwarded queries bypass the TUN.
    pub bind_interface: String,
}

impl Default for DnsInterceptConfig {
    fn default() -> Self {
        Self {
            system_dns: Ipv4Addr::new(0, 0, 0, 0), // Will be detected
            bind_interface: String::new(),         // Will be detected
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
    
}
