//! TUN device creation and OS routing configuration.
//!
//! This module handles creating a virtual network interface (TUN device)
//! and configuring OS-level routing to direct traffic to it.

use anyhow::{Context, Result};
use std::net::Ipv4Addr;
use std::process::Command;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tracing::{debug, info, warn};
use tun2::AsyncDevice;

/// Configuration for the TUN device.
#[allow(dead_code)]
#[derive(Debug, Clone)]
pub struct TunConfig {
    /// Name of the TUN device (e.g., "utun8" on macOS).
    pub name: Option<String>,
    /// IP address to assign to the TUN device.
    pub address: Ipv4Addr,
    /// Netmask for the TUN device.
    pub netmask: Ipv4Addr,
    /// MTU for the TUN device.
    pub mtu: u16,
    /// The CIDR range to route through the TUN device (e.g., "198.18.0.0/16").
    pub route_cidr: String,
}

impl Default for TunConfig {
    fn default() -> Self {
        Self {
            name: None, // Let the OS assign a name
            address: Ipv4Addr::new(198, 18, 0, 1),
            netmask: Ipv4Addr::new(255, 255, 0, 0),
            mtu: 1500,
            route_cidr: "198.18.0.0/16".to_string(),
        }
    }
}

/// Wrapper around the TUN device providing async read/write operations.
pub struct TunDevice {
    device: Option<AsyncDevice>,
    config: TunConfig,
}
#[allow(dead_code)]
impl TunDevice {
    /// Creates a new TUN device with the given configuration.
    ///
    /// This requires root/sudo privileges on most systems.
    pub async fn create(config: TunConfig) -> Result<Self> {
        info!("Creating TUN device with address {}", config.address);

        let mut tun_config = tun2::Configuration::default();

        tun_config
            .address(config.address)
            .netmask(config.netmask)
            .mtu(config.mtu)
            .up();

        #[cfg(target_os = "linux")]
        {
            // On Linux, we can set the device name
            if let Some(ref name) = config.name {
                tun_config.tun_name(name);
            }
        }

        let device = tun2::create_as_async(&tun_config)
            .context("Failed to create TUN device. Are you running as root/sudo?")?;

        let tun_device = Self {
            device: Some(device),
            config,
        };

        // Configure routing after device creation
        tun_device.configure_routes()?;

        Ok(tun_device)
    }

    /// Gets the name of the TUN device.
    pub fn name(&self) -> String {
        self.device
            .as_ref()
            .and_then(|d| d.as_ref().tun_name().ok())
            .unwrap_or_else(|| "utun".to_string())
    }

    /// Consumes the TunDevice and returns the inner AsyncDevice.
    ///
    /// This allows passing the device to other components (like NetworkStack)
    /// while keeping route configuration in place. Routes will NOT be cleaned up.
    pub fn into_async_device(mut self) -> Option<AsyncDevice> {
        self.device.take()
    }

    /// Configures OS routing to direct traffic to the TUN device.
    fn configure_routes(&self) -> Result<()> {
        let device_name = self.name();
        info!(
            "Configuring routes: {} -> {}",
            self.config.route_cidr, device_name
        );

        #[cfg(target_os = "macos")]
        {
            self.configure_macos_routes(&device_name)?;
        }

        #[cfg(target_os = "linux")]
        {
            self.configure_linux_routes(&device_name)?;
        }

        Ok(())
    }

    #[cfg(target_os = "macos")]
    fn configure_macos_routes(&self, device_name: &str) -> Result<()> {
        // Parse the CIDR to get network and prefix
        let parts: Vec<&str> = self.config.route_cidr.split('/').collect();
        let network = parts[0];
        let _prefix = parts.get(1).unwrap_or(&"16");

        // Add route for the VIP range
        // On macOS, we use: route -n add -net <network> -interface <device>
        let output = Command::new("route")
            .args(["-n", "add", "-net", network, "-interface", device_name])
            .output()
            .context("Failed to execute route command")?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            // Route might already exist, which is fine
            if !stderr.contains("File exists") {
                warn!("Route command warning: {}", stderr);
            }
        } else {
            debug!(
                "Added route for {} via {}",
                self.config.route_cidr, device_name
            );
        }

        Ok(())
    }

    #[cfg(target_os = "linux")]
    fn configure_linux_routes(&self, device_name: &str) -> Result<()> {
        // On Linux, use ip route
        let output = Command::new("ip")
            .args(["route", "add", &self.config.route_cidr, "dev", device_name])
            .output()
            .context("Failed to execute ip route command")?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            if !stderr.contains("File exists") {
                warn!("Route command warning: {}", stderr);
            }
        } else {
            debug!(
                "Added route for {} via {}",
                self.config.route_cidr, device_name
            );
        }

        Ok(())
    }

    /// Reads a packet from the TUN device.
    ///
    /// Returns the number of bytes read and fills the buffer with the raw IP packet.
    pub async fn read(&mut self, buf: &mut [u8]) -> Result<usize> {
        let device = self
            .device
            .as_mut()
            .context("TUN device was already taken")?;
        let n = device
            .read(buf)
            .await
            .context("Failed to read from TUN device")?;
        Ok(n)
    }

    /// Writes a packet to the TUN device.
    pub async fn write(&mut self, buf: &[u8]) -> Result<usize> {
        let device = self
            .device
            .as_mut()
            .context("TUN device was already taken")?;
        let n = device
            .write(buf)
            .await
            .context("Failed to write to TUN device")?;
        Ok(n)
    }

    /// Flushes any pending writes.
    pub async fn flush(&mut self) -> Result<()> {
        let device = self
            .device
            .as_mut()
            .context("TUN device was already taken")?;
        device.flush().await.context("Failed to flush TUN device")?;
        Ok(())
    }

    /// Cleans up routes when the device is dropped.
    pub fn cleanup_routes(&self) -> Result<()> {
        let device_name = self.name();
        info!("Cleaning up routes for {}", device_name);

        #[cfg(target_os = "macos")]
        {
            let parts: Vec<&str> = self.config.route_cidr.split('/').collect();
            let network = parts[0];

            let _ = Command::new("route")
                .args(["-n", "delete", "-net", network])
                .output();
        }

        #[cfg(target_os = "linux")]
        {
            let _ = Command::new("ip")
                .args(["route", "del", &self.config.route_cidr])
                .output();
        }

        Ok(())
    }
}

impl Drop for TunDevice {
    fn drop(&mut self) {
        // Only cleanup routes if the device wasn't taken via into_async_device()
        // If device was taken, routes should remain in place for the new owner
        if self.device.is_some() {
            if let Err(e) = self.cleanup_routes() {
                warn!("Failed to cleanup routes: {}", e);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = TunConfig::default();
        assert_eq!(config.address, Ipv4Addr::new(198, 18, 0, 1));
        assert_eq!(config.route_cidr, "198.18.0.0/16");
    }
}
