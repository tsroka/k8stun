//! DNS interception module.
//!
//! This module handles intercepting DNS traffic by:
//! 1. Detecting the system's DNS server
//! 2. Routing DNS server traffic through the TUN device (TunRoute mode)
//!
//! For macOS Forward mode, see the `dns_forward_macos` module.

use anyhow::{anyhow, Context, Result};
use clap::ValueEnum;
use std::fmt::Display;
use std::net::Ipv4Addr;
use std::process::Command;
use std::str::FromStr;
use tracing::{debug, info, warn};

/// DNS interception mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, ValueEnum)]
pub enum DnsMode {
    /// DNS interception is disabled.
    Disabled,
    /// Route DNS traffic through the TUN device (current behavior).
    /// Works on all platforms.
    #[default]
    TunRoute,
    /// Change system DNS settings to point to our DNS server (macOS only).
    /// This modifies the system's DNS configuration via SCDynamicStore.
    Forward,
}

impl std::fmt::Display for DnsMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DnsMode::Disabled => write!(f, "disabled"),
            DnsMode::TunRoute => write!(f, "tun_route"),
            DnsMode::Forward => write!(f, "forward"),
        }
    }
}

impl FromStr for DnsMode {
    type Err = String;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "disabled" => Ok(DnsMode::Disabled),
            "tun_route" | "tunroute" | "tun-route" => Ok(DnsMode::TunRoute),
            "forward" => Ok(DnsMode::Forward),
            _ => Err(format!(
                "Invalid DNS mode: '{}'. Valid options: disabled, tun_route, forward",
                s
            )),
        }
    }
}
#[derive(Debug, Clone)]
pub struct SystemDnsInfo {
    /// The system's original DNS server that we'll intercept.
    pub ip: Ipv4Addr,
    /// The network interface name to bind to when forwarding DNS.
    /// This ensures forwarded queries bypass the TUN.
    pub bind_interface: String,
}

impl SystemDnsInfo {
    pub fn detect() -> Result<Self> {
        // Detect system DNS and interface for upstream forwarding
        let system_dns = detect_system_dns()?;

        let bind_interface = detect_default_interface_name()?;
        Ok(Self {
            ip: system_dns,
            bind_interface,
        })
    }
}

impl Display for SystemDnsInfo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Ip: {}, Interface: {}", self.ip, self.bind_interface)
    }
}
/// Manages DNS interception lifecycle.
pub struct DnsInterceptor {
    original_route: Option<String>,
    tun_device_name: String,
}

impl DnsInterceptor {
    /// Creates a new DNS interceptor.
    ///
    /// Detects the system DNS server and the interface to bind to for forwarding.
    pub fn new(tun_device_name: String) -> Self {
        Self {
            original_route: None,
            tun_device_name,
        }
    }

    /// Enables DNS interception by routing DNS traffic through the TUN.
    pub fn enable(&mut self, dns_info: &SystemDnsInfo) -> Result<()> {
        // Don't intercept if system DNS is localhost or in our VIP range
        if dns_info.ip.is_loopback() || is_in_vip_range(dns_info.ip) {
            return Err(anyhow!(
                "Cannot intercept DNS server {} - it's localhost or in VIP range",
                dns_info.ip
            ));
        }

        info!(
            "Enabling DNS interception: {} -> TUN (forward via interface '{}')",
            dns_info.ip, dns_info.bind_interface
        );

        // Save original route (if any) and add new route through TUN
        self.add_dns_route(dns_info.ip)?;

        Ok(())
    }

    /// Disables DNS interception and restores original routing.
    pub fn disable(&mut self) -> Result<()> {
        info!("Disabling DNS interception");
        self.remove_dns_route()?;
        Ok(())
    }

    #[cfg(target_os = "macos")]
    fn add_dns_route(&mut self, dns_ip: Ipv4Addr) -> Result<()> {
        let dns_ip = dns_ip.to_string();

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
    fn add_dns_route(&mut self, dns_ip: Ipv4Addr) -> Result<()> {
        let dns_ip = dns_ip.to_string();

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
pub fn detect_system_dns() -> Result<Ipv4Addr> {
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
pub fn detect_system_dns() -> Result<Ipv4Addr> {
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
pub fn detect_default_interface_name() -> Result<String> {
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
