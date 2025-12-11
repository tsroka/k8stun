//! API-specific data transfer objects.

use serde::Serialize;
use std::net::Ipv4Addr;

use crate::vip::{PodId, ServiceId, TargetId, VipStatsSnapshot, VipUpdate};

/// Information about a single VIP mapping.
#[derive(Debug, Clone, Serialize)]
pub struct VipInfo {
    /// The virtual IP address.
    pub vip: Ipv4Addr,
    /// The target (service or pod) this VIP maps to.
    pub target: TargetInfo,
    /// Current statistics for this VIP.
    pub stats: VipStatsSnapshot,
}

/// Target information for API responses.
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum TargetInfo {
    Service { name: String, namespace: String },
    Pod { name: String, namespace: String },
}

impl From<&ServiceId> for TargetInfo {
    fn from(svc: &ServiceId) -> Self {
        TargetInfo::Service {
            name: svc.name.clone(),
            namespace: svc.namespace.clone(),
        }
    }
}

impl From<&PodId> for TargetInfo {
    fn from(pod: &PodId) -> Self {
        TargetInfo::Pod {
            name: pod.name.clone(),
            namespace: pod.namespace.clone(),
        }
    }
}

impl From<&TargetId> for TargetInfo {
    fn from(target: &TargetId) -> Self {
        match target {
            TargetId::Service(svc) => TargetInfo::from(svc),
            TargetId::Pod(pod) => TargetInfo::from(pod),
        }
    }
}

/// A snapshot of all VIP mappings.
#[derive(Debug, Clone, Serialize)]
pub struct VipSnapshot {
    /// List of all current VIP mappings.
    pub vips: Vec<VipInfo>,
}

/// SSE event wrapper for VIP updates.
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum VipEvent {
    /// Initial snapshot of all VIPs (sent on connection).
    Snapshot { vips: Vec<VipInfo> },
    /// A VIP was allocated.
    VipAllocated { vip: Ipv4Addr, target: TargetInfo },
    /// A VIP was removed.
    VipRemoved { vip: Ipv4Addr, target: TargetInfo },
    /// Connection count changed.
    ConnectionChanged {
        vip: Ipv4Addr,
        active_connections: u32,
        total_connections: u64,
    },
}

impl VipEvent {
    /// Creates an event from a VipUpdate.
    pub fn from_update(update: VipUpdate) -> Self {
        match update {
            VipUpdate::VipAllocated { vip, target } => VipEvent::VipAllocated {
                vip,
                target: TargetInfo::from(&target),
            },
            VipUpdate::VipRemoved { vip, target } => VipEvent::VipRemoved {
                vip,
                target: TargetInfo::from(&target),
            },
            VipUpdate::ConnectionChanged {
                vip,
                active_connections,
                total_connections,
            } => VipEvent::ConnectionChanged {
                vip,
                active_connections,
                total_connections,
            },
        }
    }
}

