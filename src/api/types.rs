//! API-specific data transfer objects.

use chrono::{DateTime, Utc};
use serde::Serialize;
use std::net::Ipv4Addr;

use crate::vip::{
    ConnectionEventType, ConnectionInfo, PodId, ServiceId, TargetId, VipAllocation,
    VipStatsSnapshot, VipUpdate,
};

/// Information about an active connection.
#[derive(Debug, Clone, Serialize)]
pub struct ConnectionInfoDto {
    /// When the connection was created (RFC3339 format).
    pub created_at: DateTime<Utc>,
    /// Source IP address (who initiated the connection).
    pub src_ip: Ipv4Addr,
    /// Source port.
    pub src_port: u16,
    /// Destination port.
    pub dst_port: u16,
}

impl From<&ConnectionInfo> for ConnectionInfoDto {
    fn from(info: &ConnectionInfo) -> Self {
        Self {
            created_at: info.created_at,
            src_ip: info.src_ip,
            src_port: info.src_port,
            dst_port: info.dst_port,
        }
    }
}

/// Information about a single VIP mapping.
#[derive(Debug, Clone, Serialize)]
pub struct VipInfo {
    /// The virtual IP address.
    pub vip: Ipv4Addr,
    /// The target (service or pod) this VIP maps to.
    pub target: TargetInfo,
    /// When this VIP was allocated (RFC3339 format).
    pub allocated_at: DateTime<Utc>,
    /// Current statistics for this VIP.
    pub stats: VipStatsSnapshot,
    /// Currently active connections.
    pub connections: Vec<ConnectionInfoDto>,
}

impl From<VipAllocation> for VipInfo {
    fn from(alloc: VipAllocation) -> Self {
        Self {
            vip: alloc.vip,
            target: TargetInfo::from(&alloc.target),
            allocated_at: alloc.allocated_at,
            stats: alloc.stats,
            connections: alloc
                .connections
                .iter()
                .map(ConnectionInfoDto::from)
                .collect(),
        }
    }
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
        event_type: ConnectionEventType,
        connection: ConnectionInfoDto,
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
                event_type,
                connection,
                active_connections,
                total_connections,
            } => VipEvent::ConnectionChanged {
                vip,
                event_type,
                connection: ConnectionInfoDto::from(&connection),
                active_connections,
                total_connections,
            },
        }
    }
}
