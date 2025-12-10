//! Virtual IP (VIP) pool management.
//!
//! This module manages the allocation of virtual IP addresses from a pool
//! and maintains bidirectional mappings between VIPs and Kubernetes service names.

#![allow(dead_code)]

use anyhow::{anyhow, Result};
use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{debug, info};

/// Represents a Kubernetes service identifier.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ServiceId {
    /// The service name.
    pub name: String,
    /// The namespace the service is in.
    pub namespace: String,
    /// The target port on the service.
    pub port: u16,
}

impl ServiceId {
    pub fn new(name: impl Into<String>, namespace: impl Into<String>, port: u16) -> Self {
        Self {
            name: name.into(),
            namespace: namespace.into(),
            port,
        }
    }

    /// Parses a service identifier from a DNS-like name.
    /// Supports formats like:
    /// - `service.namespace` (assumes port 80)
    /// - `service.namespace.svc.cluster.local` (assumes port 80)
    pub fn from_dns_name(name: &str, port: u16) -> Option<Self> {
        let name = name.trim_end_matches('.');

        // Try to parse as service.namespace.svc.cluster.local
        if let Some(stripped) = name.strip_suffix(".svc.cluster.local") {
            let parts: Vec<&str> = stripped.splitn(2, '.').collect();
            if parts.len() == 2 {
                return Some(Self::new(parts[0], parts[1], port));
            }
        }

        // Try to parse as service.namespace
        let parts: Vec<&str> = name.splitn(2, '.').collect();
        if parts.len() == 2 {
            return Some(Self::new(parts[0], parts[1], port));
        }

        None
    }

    /// Returns the full DNS name for this service.
    pub fn dns_name(&self) -> String {
        format!("{}.{}.svc.cluster.local", self.name, self.namespace)
    }

    /// Returns a short DNS name (service.namespace).
    pub fn short_dns_name(&self) -> String {
        format!("{}.{}", self.name, self.namespace)
    }
}

/// Manages the Virtual IP pool and service mappings.
pub struct VipManager {
    /// The base IP address for the VIP pool (e.g., 198.18.0.0).
    base_ip: Ipv4Addr,
    /// The next available IP offset.
    next_offset: Arc<RwLock<u32>>,
    /// Mapping from VIP to service ID.
    vip_to_service: Arc<RwLock<HashMap<Ipv4Addr, ServiceId>>>,
    /// Mapping from service ID to VIP.
    service_to_vip: Arc<RwLock<HashMap<ServiceId, Ipv4Addr>>>,
    /// Maximum number of IPs in the pool.
    max_ips: u32,
}

impl VipManager {
    /// Creates a new VIP manager with the given base IP.
    ///
    /// The pool will allocate IPs starting from base_ip + 2 (reserving .0 for network and .1 for gateway).
    pub fn new(base_ip: Ipv4Addr) -> Self {
        info!("Initializing VIP manager with base IP: {}", base_ip);
        Self {
            base_ip,
            next_offset: Arc::new(RwLock::new(2)), // Start at .2 (skip .0 and .1)
            vip_to_service: Arc::new(RwLock::new(HashMap::new())),
            service_to_vip: Arc::new(RwLock::new(HashMap::new())),
            max_ips: 65534, // /16 network minus network and broadcast
        }
    }

    /// Allocates or retrieves a VIP for the given service.
    ///
    /// If the service already has a VIP assigned, returns the existing one.
    /// Otherwise, allocates a new VIP from the pool.
    pub async fn get_or_allocate_vip(&self, service: ServiceId) -> Result<Ipv4Addr> {
        // Check if service already has a VIP
        {
            let service_map = self.service_to_vip.read().await;
            if let Some(&vip) = service_map.get(&service) {
                debug!("Returning existing VIP {} for {:?}", vip, service);
                return Ok(vip);
            }
        }

        // Allocate a new VIP
        let vip = self.allocate_next_vip().await?;

        // Insert mappings
        {
            let mut vip_map = self.vip_to_service.write().await;
            let mut service_map = self.service_to_vip.write().await;

            vip_map.insert(vip, service.clone());
            service_map.insert(service.clone(), vip);
        }

        info!("Allocated VIP {} for {:?}", vip, service);
        Ok(vip)
    }

    /// Allocates the next available VIP from the pool.
    async fn allocate_next_vip(&self) -> Result<Ipv4Addr> {
        let mut offset = self.next_offset.write().await;

        if *offset >= self.max_ips {
            return Err(anyhow!("VIP pool exhausted"));
        }

        let base_u32 = u32::from(self.base_ip);
        let vip = Ipv4Addr::from(base_u32 + *offset);
        *offset += 1;

        Ok(vip)
    }

    /// Looks up the service associated with a VIP.
    pub async fn lookup_service(&self, vip: Ipv4Addr) -> Option<ServiceId> {
        let vip_map = self.vip_to_service.read().await;
        vip_map.get(&vip).cloned()
    }

    /// Looks up the VIP associated with a service.
    pub async fn lookup_vip(&self, service: &ServiceId) -> Option<Ipv4Addr> {
        let service_map = self.service_to_vip.read().await;
        service_map.get(service).copied()
    }

    /// Checks if an IP address is within the VIP pool range.
    pub fn is_vip(&self, ip: Ipv4Addr) -> bool {
        let base_u32 = u32::from(self.base_ip);
        let ip_u32 = u32::from(ip);

        ip_u32 >= base_u32 && ip_u32 < base_u32 + self.max_ips
    }

    /// Returns all currently allocated VIP mappings.
    pub async fn get_all_mappings(&self) -> Vec<(Ipv4Addr, ServiceId)> {
        let vip_map = self.vip_to_service.read().await;
        vip_map
            .iter()
            .map(|(&vip, svc)| (vip, svc.clone()))
            .collect()
    }

    /// Pre-allocates VIPs for a list of services.
    pub async fn pre_allocate(&self, services: Vec<ServiceId>) -> Result<()> {
        for service in services {
            self.get_or_allocate_vip(service).await?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_service_id_from_dns_name() {
        let svc = ServiceId::from_dns_name("backend.default", 80).unwrap();
        assert_eq!(svc.name, "backend");
        assert_eq!(svc.namespace, "default");
        assert_eq!(svc.port, 80);

        let svc = ServiceId::from_dns_name("api.production.svc.cluster.local", 8080).unwrap();
        assert_eq!(svc.name, "api");
        assert_eq!(svc.namespace, "production");
        assert_eq!(svc.port, 8080);
    }

    #[test]
    fn test_service_id_dns_names() {
        let svc = ServiceId::new("backend", "default", 80);
        assert_eq!(svc.dns_name(), "backend.default.svc.cluster.local");
        assert_eq!(svc.short_dns_name(), "backend.default");
    }

    #[tokio::test]
    async fn test_vip_allocation() {
        let manager = VipManager::new(Ipv4Addr::new(198, 18, 0, 0));

        let svc1 = ServiceId::new("svc1", "default", 80);
        let svc2 = ServiceId::new("svc2", "default", 80);

        let vip1 = manager.get_or_allocate_vip(svc1.clone()).await.unwrap();
        let vip2 = manager.get_or_allocate_vip(svc2.clone()).await.unwrap();

        // Should get different VIPs
        assert_ne!(vip1, vip2);

        // First VIP should be .2 (skipping .0 and .1)
        assert_eq!(vip1, Ipv4Addr::new(198, 18, 0, 2));
        assert_eq!(vip2, Ipv4Addr::new(198, 18, 0, 3));

        // Same service should return same VIP
        let vip1_again = manager.get_or_allocate_vip(svc1).await.unwrap();
        assert_eq!(vip1, vip1_again);
    }

    #[test]
    fn test_is_vip() {
        let manager = VipManager::new(Ipv4Addr::new(198, 18, 0, 0));

        assert!(manager.is_vip(Ipv4Addr::new(198, 18, 0, 1)));
        assert!(manager.is_vip(Ipv4Addr::new(198, 18, 255, 253))); // Within pool range
        assert!(!manager.is_vip(Ipv4Addr::new(198, 19, 0, 0)));
        assert!(!manager.is_vip(Ipv4Addr::new(192, 168, 1, 1)));
    }
}
