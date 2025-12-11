//! Virtual IP (VIP) pool management.
//!
//! This module manages the allocation of virtual IP addresses from a pool
//! and maintains bidirectional mappings between VIPs and Kubernetes service/pod names.

#![allow(dead_code)]

use anyhow::{anyhow, Result};
use dashmap::DashMap;
use std::net::Ipv4Addr;
use std::sync::atomic::{AtomicU32, Ordering};
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

/// Represents a Kubernetes pod identifier.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct PodId {
    /// The pod name.
    pub name: String,
    /// The namespace the pod is in.
    pub namespace: String,
    /// The target port on the pod.
    pub port: u16,
}

impl PodId {
    pub fn new(name: impl Into<String>, namespace: impl Into<String>, port: u16) -> Self {
        Self {
            name: name.into(),
            namespace: namespace.into(),
            port,
        }
    }

    /// Returns the full DNS name for this pod (IP-based format).
    pub fn dns_name(&self) -> String {
        format!("{}.{}.pod.cluster.local", self.name, self.namespace)
    }
}

/// Unified target identifier that can be either a service or a pod.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum TargetId {
    Service(ServiceId),
    Pod(PodId),
}

impl TargetId {
    /// Returns the namespace of the target.
    pub fn namespace(&self) -> &str {
        match self {
            TargetId::Service(s) => &s.namespace,
            TargetId::Pod(p) => &p.namespace,
        }
    }

    /// Returns the name of the target.
    pub fn name(&self) -> &str {
        match self {
            TargetId::Service(s) => &s.name,
            TargetId::Pod(p) => &p.name,
        }
    }

    /// Returns the port of the target.
    pub fn port(&self) -> u16 {
        match self {
            TargetId::Service(s) => s.port,
            TargetId::Pod(p) => p.port,
        }
    }

    /// Returns true if this is a service target.
    pub fn is_service(&self) -> bool {
        matches!(self, TargetId::Service(_))
    }

    /// Returns true if this is a pod target.
    pub fn is_pod(&self) -> bool {
        matches!(self, TargetId::Pod(_))
    }
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

/// Manages the Virtual IP pool and service/pod mappings.
pub struct VipManager {
    /// The base IP address for the VIP pool (e.g., 198.18.0.0).
    base_ip: Ipv4Addr,
    /// The next available IP offset (atomic for lock-free increment).
    next_offset: AtomicU32,
    /// Mapping from VIP to target (service or pod).
    vip_to_target: DashMap<Ipv4Addr, TargetId>,
    /// Mapping from target to VIP.
    target_to_vip: DashMap<TargetId, Ipv4Addr>,
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
            next_offset: AtomicU32::new(2), // Start at .2 (skip .0 and .1)
            vip_to_target: DashMap::new(),
            target_to_vip: DashMap::new(),
            max_ips: 65534, // /16 network minus network and broadcast
        }
    }

    /// Allocates or retrieves a VIP for the given service.
    ///
    /// If the service already has a VIP assigned, returns the existing one.
    /// Otherwise, allocates a new VIP from the pool.
    pub async fn get_or_allocate_vip(&self, service: ServiceId) -> Result<Ipv4Addr> {
        self.get_or_allocate_vip_for_target(TargetId::Service(service))
            .await
    }

    /// Allocates or retrieves a VIP for the given pod.
    ///
    /// If the pod already has a VIP assigned, returns the existing one.
    /// Otherwise, allocates a new VIP from the pool.
    pub async fn get_or_allocate_vip_for_pod(&self, pod: PodId) -> Result<Ipv4Addr> {
        self.get_or_allocate_vip_for_target(TargetId::Pod(pod))
            .await
    }

    /// Allocates or retrieves a VIP for the given target (service or pod).
    ///
    /// If the target already has a VIP assigned, returns the existing one.
    /// Otherwise, allocates a new VIP from the pool.
    pub async fn get_or_allocate_vip_for_target(&self, target: TargetId) -> Result<Ipv4Addr> {
        // Check if target already has a VIP (lock-free read)
        if let Some(vip) = self.target_to_vip.get(&target) {
            debug!("Returning existing VIP {} for {:?}", *vip, target);
            return Ok(*vip);
        }

        // Allocate a new VIP
        let vip = self.allocate_next_vip()?;

        // Insert mappings (DashMap handles concurrent access)
        self.vip_to_target.insert(vip, target.clone());
        self.target_to_vip.insert(target.clone(), vip);

        info!("Allocated VIP {} for {:?}", vip, target);
        Ok(vip)
    }

    /// Allocates the next available VIP from the pool.
    fn allocate_next_vip(&self) -> Result<Ipv4Addr> {
        let offset = self.next_offset.fetch_add(1, Ordering::SeqCst);

        if offset >= self.max_ips {
            return Err(anyhow!("VIP pool exhausted"));
        }

        let base_u32 = u32::from(self.base_ip);
        let vip = Ipv4Addr::from(base_u32 + offset);

        Ok(vip)
    }

    /// Looks up the target (service or pod) associated with a VIP.
    pub async fn lookup_target(&self, vip: Ipv4Addr) -> Option<TargetId> {
        self.vip_to_target.get(&vip).map(|r| r.value().clone())
    }

    /// Looks up the service associated with a VIP.
    /// Returns None if the VIP is not allocated or is allocated to a pod.
    pub async fn lookup_service(&self, vip: Ipv4Addr) -> Option<ServiceId> {
        self.vip_to_target.get(&vip).and_then(|r| match r.value() {
            TargetId::Service(s) => Some(s.clone()),
            TargetId::Pod(_) => None,
        })
    }

    /// Looks up the pod associated with a VIP.
    /// Returns None if the VIP is not allocated or is allocated to a service.
    pub async fn lookup_pod(&self, vip: Ipv4Addr) -> Option<PodId> {
        self.vip_to_target.get(&vip).and_then(|r| match r.value() {
            TargetId::Pod(p) => Some(p.clone()),
            TargetId::Service(_) => None,
        })
    }

    /// Looks up the VIP associated with a service.
    pub async fn lookup_vip(&self, service: &ServiceId) -> Option<Ipv4Addr> {
        self.target_to_vip
            .get(&TargetId::Service(service.clone()))
            .map(|r| *r.value())
    }

    /// Looks up the VIP associated with a pod.
    pub async fn lookup_vip_for_pod(&self, pod: &PodId) -> Option<Ipv4Addr> {
        self.target_to_vip
            .get(&TargetId::Pod(pod.clone()))
            .map(|r| *r.value())
    }

    /// Checks if an IP address is within the VIP pool range.
    pub fn is_vip(&self, ip: Ipv4Addr) -> bool {
        let base_u32 = u32::from(self.base_ip);
        let ip_u32 = u32::from(ip);

        ip_u32 >= base_u32 && ip_u32 < base_u32 + self.max_ips
    }

    /// Returns all currently allocated VIP mappings for services.
    pub async fn get_all_mappings(&self) -> Vec<(Ipv4Addr, ServiceId)> {
        self.vip_to_target
            .iter()
            .filter_map(|entry| match entry.value() {
                TargetId::Service(svc) => Some((*entry.key(), svc.clone())),
                TargetId::Pod(_) => None,
            })
            .collect()
    }

    /// Returns all currently allocated VIP mappings (both services and pods).
    pub async fn get_all_target_mappings(&self) -> Vec<(Ipv4Addr, TargetId)> {
        self.vip_to_target
            .iter()
            .map(|entry| (*entry.key(), entry.value().clone()))
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

    #[test]
    fn test_pod_id() {
        let pod = PodId::new("mysql-0", "default", 3306);
        assert_eq!(pod.name, "mysql-0");
        assert_eq!(pod.namespace, "default");
        assert_eq!(pod.port, 3306);
        assert_eq!(pod.dns_name(), "mysql-0.default.pod.cluster.local");
    }

    #[test]
    fn test_target_id() {
        let svc = ServiceId::new("backend", "default", 80);
        let pod = PodId::new("mysql-0", "default", 3306);

        let target_svc = TargetId::Service(svc.clone());
        let target_pod = TargetId::Pod(pod.clone());

        assert!(target_svc.is_service());
        assert!(!target_svc.is_pod());
        assert_eq!(target_svc.name(), "backend");
        assert_eq!(target_svc.namespace(), "default");
        assert_eq!(target_svc.port(), 80);

        assert!(target_pod.is_pod());
        assert!(!target_pod.is_service());
        assert_eq!(target_pod.name(), "mysql-0");
        assert_eq!(target_pod.namespace(), "default");
        assert_eq!(target_pod.port(), 3306);
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

    #[tokio::test]
    async fn test_pod_vip_allocation() {
        let manager = VipManager::new(Ipv4Addr::new(198, 18, 0, 0));

        let pod1 = PodId::new("mysql-0", "default", 3306);
        let pod2 = PodId::new("mysql-1", "default", 3306);

        let vip1 = manager
            .get_or_allocate_vip_for_pod(pod1.clone())
            .await
            .unwrap();
        let vip2 = manager
            .get_or_allocate_vip_for_pod(pod2.clone())
            .await
            .unwrap();

        // Should get different VIPs
        assert_ne!(vip1, vip2);

        // Same pod should return same VIP
        let vip1_again = manager
            .get_or_allocate_vip_for_pod(pod1.clone())
            .await
            .unwrap();
        assert_eq!(vip1, vip1_again);

        // Lookup should work
        assert_eq!(manager.lookup_pod(vip1).await, Some(pod1));
        assert_eq!(manager.lookup_pod(vip2).await, Some(pod2));
        assert_eq!(manager.lookup_service(vip1).await, None);
    }

    #[tokio::test]
    async fn test_mixed_allocation() {
        let manager = VipManager::new(Ipv4Addr::new(198, 18, 0, 0));

        let svc = ServiceId::new("mysql", "default", 3306);
        let pod = PodId::new("mysql-0", "default", 3306);

        let svc_vip = manager.get_or_allocate_vip(svc.clone()).await.unwrap();
        let pod_vip = manager
            .get_or_allocate_vip_for_pod(pod.clone())
            .await
            .unwrap();

        // Should get different VIPs
        assert_ne!(svc_vip, pod_vip);

        // Lookup should return correct types
        assert_eq!(manager.lookup_service(svc_vip).await, Some(svc.clone()));
        assert_eq!(manager.lookup_pod(svc_vip).await, None);
        assert_eq!(manager.lookup_pod(pod_vip).await, Some(pod.clone()));
        assert_eq!(manager.lookup_service(pod_vip).await, None);

        // Target lookup should work
        assert_eq!(
            manager.lookup_target(svc_vip).await,
            Some(TargetId::Service(svc))
        );
        assert_eq!(
            manager.lookup_target(pod_vip).await,
            Some(TargetId::Pod(pod))
        );
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
