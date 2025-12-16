//! macOS DNS forwarding module.
//!
//! This module handles changing macOS system DNS settings to point to our DNS server.
//! It uses the `system-configuration` crate to:
//! - Read current DNS settings
//! - Backup original DNS configuration
//! - Set new DNS servers pointing to the TUN interface
//! - Monitor for DNS changes and log them
//! - Restore original settings on cleanup
//!
//! This is inspired by the Mullvad VPN implementation:
//! https://github.com/mullvad/mullvadvpn-app/blob/main/talpid-dns/src/macos.rs

use anyhow::{anyhow, Result};
use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::sync::{Arc, Mutex};
use std::thread;
use system_configuration::core_foundation::array::CFArray;
use system_configuration::core_foundation::base::{TCFType, ToVoid};
use system_configuration::core_foundation::dictionary::CFMutableDictionary;
use system_configuration::core_foundation::number::CFNumber;
use system_configuration::core_foundation::runloop::{kCFRunLoopCommonModes, CFRunLoop};
use system_configuration::core_foundation::string::CFString;
use system_configuration::dynamic_store::{
    SCDynamicStore, SCDynamicStoreBuilder, SCDynamicStoreCallBackContext,
};
use system_configuration::sys::schema_definitions::{
    kSCPropNetDNSServerAddresses, kSCPropNetDNSServerPort,
};
use tracing::{debug, info, warn};

/// Standard DNS port.
const DNS_PORT: u16 = 53;

/// Pattern to match all DNS state entries.
const STATE_PATH_PATTERN: &str = "State:/Network/Service/.*/DNS";

/// Pattern to match all DNS setup entries.
const SETUP_PATH_PATTERN: &str = "Setup:/Network/Service/.*/DNS";

/// A single DNS configuration entry (for one network service).
#[derive(Debug, Clone)]
struct DnsSettings {
    /// DNS server addresses as strings.
    server_addresses: Vec<String>,
    /// DNS server port (if non-standard).
    port: Option<u16>,
    /// The service path this settings came from.
    service_path: String,
}

impl DnsSettings {
    /// Creates new DNS settings with the given server addresses.
    fn new(server_addresses: Vec<String>, port: u16, service_path: String) -> Self {
        Self {
            server_addresses,
            port: if port != DNS_PORT { Some(port) } else { None },
            service_path,
        }
    }

    /// Loads DNS settings from a dynamic store path.
    fn load(store: &SCDynamicStore, path: &str) -> Option<Self> {
        let path_cf = CFString::new(path);
        let dict = store.get(path_cf)?;

        // Try to get server addresses using a simpler approach
        // Access the property list value and try to extract server addresses
        let server_addresses: Vec<String> = if let Some(plist) =
            dict.downcast_into::<system_configuration::core_foundation::dictionary::CFDictionary>()
        {
            let key = unsafe { CFString::wrap_under_get_rule(kSCPropNetDNSServerAddresses) };
            if let Some(servers_ptr) = plist.find(key.to_void()) {
                // The value should be a CFArray of CFStrings
                let servers_cf = unsafe {
                    system_configuration::core_foundation::array::CFArray::<CFString>::wrap_under_get_rule(
                        *servers_ptr as *const _
                    )
                };
                servers_cf.iter().map(|s| s.to_string()).collect()
            } else {
                Vec::new()
            }
        } else {
            Vec::new()
        };

        if server_addresses.is_empty() {
            return None;
        }

        Some(Self {
            server_addresses,
            port: None, // Port parsing is complex, skip for now
            service_path: path.to_string(),
        })
    }

    /// Saves these DNS settings to the dynamic store.
    fn save(&self, store: &SCDynamicStore) -> Result<()> {
        let mut dict = CFMutableDictionary::new();

        // Set server addresses
        if !self.server_addresses.is_empty() {
            let servers: Vec<CFString> = self
                .server_addresses
                .iter()
                .map(|s| CFString::new(s))
                .collect();
            let servers_array = CFArray::from_CFTypes(&servers);
            let key = unsafe { CFString::wrap_under_get_rule(kSCPropNetDNSServerAddresses) };
            dict.add(&key.to_void(), &servers_array.to_untyped().to_void());
        }

        // Set port if non-standard
        if let Some(port) = self.port {
            let port_key = unsafe { CFString::wrap_under_get_rule(kSCPropNetDNSServerPort) };
            let port_num = CFNumber::from(port as i32);
            dict.add(&port_key.to_void(), &port_num.to_void());
        }

        let path = CFString::new(&self.service_path);
        let dict_immutable = dict.to_immutable();

        if !store.set(path, dict_immutable) {
            return Err(anyhow!("Failed to set DNS at path: {}", self.service_path));
        }

        debug!(
            "Saved DNS settings to {}: {:?}",
            self.service_path, self.server_addresses
        );
        Ok(())
    }
}

/// State for the DNS forwarder.
struct ForwarderState {
    /// Original DNS settings that were backed up.
    backup: HashMap<String, Option<DnsSettings>>,
    /// The DNS settings we're enforcing.
    #[allow(dead_code)]
    current_settings: Option<DnsSettings>,
}

impl ForwarderState {
    fn new() -> Self {
        Self {
            backup: HashMap::new(),
            current_settings: None,
        }
    }
}

/// Manages macOS DNS settings for forward mode.
///
/// This struct handles:
/// - Backing up current DNS settings
/// - Setting DNS to point to our server
/// - Monitoring for external DNS changes
/// - Restoring original settings on cleanup
pub struct DnsForwarder {
    /// The DNS server address to set.
    dns_server_addr: Ipv4Addr,
    /// The DNS server port.
    dns_port: u16,
    /// The TUN interface name (used as identifier).
    #[allow(dead_code)]
    tun_interface: String,
    /// Shared state protected by mutex.
    state: Arc<Mutex<ForwarderState>>,
    /// Handle to the change monitoring thread.
    monitor_thread: Option<thread::JoinHandle<()>>,
    /// Flag to stop the monitor thread.
    should_stop: Arc<std::sync::atomic::AtomicBool>,
}

impl DnsForwarder {
    /// Creates a new DNS forwarder.
    ///
    /// # Arguments
    /// * `dns_server_addr` - The IP address of our DNS server (TUN interface IP)
    /// * `dns_port` - The port our DNS server listens on
    /// * `tun_interface` - The name of the TUN interface
    pub fn new(dns_server_addr: Ipv4Addr, dns_port: u16, tun_interface: String) -> Result<Self> {
        Ok(Self {
            dns_server_addr,
            dns_port,
            tun_interface,
            state: Arc::new(Mutex::new(ForwarderState::new())),
            monitor_thread: None,
            should_stop: Arc::new(std::sync::atomic::AtomicBool::new(false)),
        })
    }

    /// Enables DNS forwarding by changing system DNS settings.
    ///
    /// This will:
    /// 1. Backup current DNS settings
    /// 2. Set all network services to use our DNS server
    /// 3. Start monitoring for DNS changes
    pub fn enable(&mut self) -> Result<()> {
        info!(
            "Enabling DNS forward mode: setting system DNS to {}:{}",
            self.dns_server_addr, self.dns_port
        );

        // Create dynamic store for reading/writing
        let store = SCDynamicStoreBuilder::new("k8stun-dns-forwarder").build();

        // Backup current DNS settings
        self.backup_dns_settings(&store)?;

        // Apply our DNS settings to all services
        self.apply_dns_settings(&store)?;

        // Start monitoring for changes
        self.start_monitor()?;

        info!("DNS forward mode enabled");
        Ok(())
    }

    /// Disables DNS forwarding and restores original settings.
    pub fn disable(&mut self) -> Result<()> {
        info!("Disabling DNS forward mode");

        // Stop the monitor thread
        self.stop_monitor();

        // Restore original DNS settings
        let store = SCDynamicStoreBuilder::new("k8stun-dns-forwarder").build();

        self.restore_dns_settings(&store)?;

        info!("DNS forward mode disabled, original settings restored");
        Ok(())
    }

    /// Backs up current DNS settings from all network services.
    fn backup_dns_settings(&self, store: &SCDynamicStore) -> Result<()> {
        let mut state = self.state.lock().unwrap();
        state.backup.clear();

        // Get all State:/.../DNS paths
        if let Some(paths) = store.get_keys(STATE_PATH_PATTERN) {
            for path in paths.iter() {
                let path_str = path.to_string();
                let settings = DnsSettings::load(store, &path_str);
                debug!(
                    "Backed up DNS from {}: {:?}",
                    path_str,
                    settings.as_ref().map(|s| &s.server_addresses)
                );
                state.backup.insert(path_str.clone(), settings);

                // Also backup corresponding Setup path
                if let Some(setup_path) = state_to_setup_path(&path_str) {
                    let setup_settings = DnsSettings::load(store, &setup_path);
                    state.backup.insert(setup_path, setup_settings);
                }
            }
        }

        // Also get Setup paths that might not have State counterparts
        if let Some(paths) = store.get_keys(SETUP_PATH_PATTERN) {
            for path in paths.iter() {
                let path_str = path.to_string();
                state.backup.entry(path_str.clone()).or_insert_with(|| {
                    let settings = DnsSettings::load(store, &path_str);
                    debug!(
                        "Backed up DNS from {}: {:?}",
                        path_str,
                        settings.as_ref().map(|s| &s.server_addresses)
                    );
                    settings
                });
            }
        }

        info!(
            "Backed up DNS settings from {} services",
            state.backup.len()
        );
        Ok(())
    }

    /// Applies our DNS settings to all network services.
    fn apply_dns_settings(&self, store: &SCDynamicStore) -> Result<()> {
        let state = self.state.lock().unwrap();
        let dns_addr = self.dns_server_addr.to_string();

        for path in state.backup.keys() {
            let settings = DnsSettings::new(vec![dns_addr.clone()], self.dns_port, path.clone());
            if let Err(e) = settings.save(store) {
                warn!("Failed to set DNS for {}: {}", path, e);
            }
        }

        info!(
            "Applied DNS settings ({}:{}) to {} services",
            self.dns_server_addr,
            self.dns_port,
            state.backup.len()
        );
        Ok(())
    }

    /// Restores original DNS settings.
    fn restore_dns_settings(&self, store: &SCDynamicStore) -> Result<()> {
        let mut state = self.state.lock().unwrap();
        for (path, settings_opt) in &state.backup {
            match settings_opt {
                Some(settings) => {
                    if let Err(e) = settings.save(store) {
                        warn!("Failed to restore DNS for {}: {}", path, e);
                    } else {
                        debug!("Restored DNS for {}", path);
                    }
                }
                None => {
                    // Original had no DNS settings, remove ours
                    let path_cf = CFString::new(path);
                    if !store.remove(path_cf) {
                        debug!("Could not remove DNS settings at {} (may not exist)", path);
                    } else {
                        debug!("Removed DNS settings at {}", path);
                    }
                }
            }
        }
        state.backup.clear();
        state.current_settings = None;
        info!("Restored original DNS settings");
        Ok(())
    }

    /// Starts the DNS change monitor thread.
    fn start_monitor(&mut self) -> Result<()> {
        self.should_stop
            .store(false, std::sync::atomic::Ordering::SeqCst);

        let should_stop = Arc::clone(&self.should_stop);
        let dns_server = self.dns_server_addr.to_string();

        let handle = thread::spawn(move || {
            run_dns_monitor(should_stop, dns_server);
        });

        self.monitor_thread = Some(handle);
        debug!("Started DNS change monitor");
        Ok(())
    }

    /// Stops the DNS change monitor thread.
    fn stop_monitor(&mut self) {
        self.should_stop
            .store(true, std::sync::atomic::Ordering::SeqCst);

        // We can't easily stop a CFRunLoop from another thread, so we just
        // signal it to stop and it will exit on the next iteration or timeout
        if let Some(handle) = self.monitor_thread.take() {
            // Give it a moment to stop, but don't block forever
            let _ = handle.join();
        }
        debug!("Stopped DNS change monitor");
    }
}

impl Drop for DnsForwarder {
    fn drop(&mut self) {
        if let Err(e) = self.disable() {
            warn!("Failed to disable DNS forwarder on drop: {}", e);
        }
    }
}

/// Converts a State: path to a Setup: path.
fn state_to_setup_path(state_path: &str) -> Option<String> {
    if state_path.starts_with("State:/") {
        Some(state_path.replacen("State:/", "Setup:/", 1))
    } else {
        None
    }
}

/// Callback function for DNS changes.
fn dns_change_callback(
    _store: SCDynamicStore,
    changed_keys: CFArray<CFString>,
    expected_dns: &mut String,
) {
    for key in changed_keys.iter() {
        let key_str = key.to_string();
        info!(
            "DNS configuration changed: {} (expected DNS: {})",
            key_str, expected_dns
        );
    }
}

/// Runs the DNS change monitor in a background thread.
fn run_dns_monitor(should_stop: Arc<std::sync::atomic::AtomicBool>, expected_dns: String) {
    info!("DNS change monitor started");

    // Create callback context
    let context = SCDynamicStoreCallBackContext {
        callout: dns_change_callback,
        info: expected_dns,
    };

    // Build dynamic store with callback
    let store = SCDynamicStoreBuilder::new("k8stun-dns-monitor")
        .callback_context(context)
        .build();

    // Set up notification keys
    let patterns = vec![
        CFString::new(STATE_PATH_PATTERN),
        CFString::new(SETUP_PATH_PATTERN),
    ];
    let patterns_array = CFArray::from_CFTypes(&patterns);

    let empty_keys: Vec<CFString> = vec![];
    let empty_array = CFArray::from_CFTypes(&empty_keys);

    if !store.set_notification_keys(&empty_array, &patterns_array) {
        warn!("Failed to set DNS notification keys");
        return;
    }

    // Add to run loop
    let run_loop_source = store.create_run_loop_source();
    let run_loop = CFRunLoop::get_current();

    unsafe {
        run_loop.add_source(&run_loop_source, kCFRunLoopCommonModes);
    }

    debug!("DNS monitor entering run loop");

    // Run until signaled to stop
    while !should_stop.load(std::sync::atomic::Ordering::SeqCst) {
        // Run for a short interval, then check if we should stop
        // Use run_in_mode with a timeout
        unsafe {
            system_configuration::core_foundation::runloop::CFRunLoopRunInMode(
                system_configuration::core_foundation::runloop::kCFRunLoopDefaultMode,
                0.5, // 500ms timeout
                1,   // return after source handled
            );
        }
    }

    info!("DNS change monitor stopped");
}
