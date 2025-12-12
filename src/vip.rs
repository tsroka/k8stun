//! Virtual IP (VIP) pool management with actor-based concurrency.
//!
//! This module manages the allocation of virtual IP addresses from a pool
//! and maintains bidirectional mappings between VIPs and Kubernetes service/pod names.
//! It uses an actor pattern with message passing for thread-safe state management,
//! and tracks active connections with RAII guards for automatic cleanup.



use anyhow::{anyhow, Result};
use chrono::{DateTime, Utc};
use serde::Serialize;
use std::cmp::Reverse;
use std::collections::{BinaryHeap, HashMap};
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{broadcast, mpsc, oneshot};
use tracing::{debug, info};

// ============================================================================
// Public Types (ServiceId, PodId, TargetId) - unchanged from original
// ============================================================================

/// Represents a Kubernetes service identifier.
///
/// Note: Port is intentionally not included here. A service gets the same VIP
/// regardless of which port you connect to. The port is determined at connection
/// time from the TCP destination port.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize)]
pub struct ServiceId {
    /// The service name.
    pub name: String,
    /// The namespace the service is in.
    pub namespace: String,
}

/// Represents a Kubernetes pod identifier.
///
/// Note: Port is intentionally not included here. A pod gets the same VIP
/// regardless of which port you connect to. The port is determined at connection
/// time from the TCP destination port.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize)]
pub struct PodId {
    /// The pod name.
    pub name: String,
    /// The namespace the pod is in.
    pub namespace: String,
}

impl PodId {
    pub fn new(name: impl Into<String>, namespace: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            namespace: namespace.into(),
        }
    }
}

/// Unified target identifier that can be either a service or a pod.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize)]
#[serde(tag = "type", rename_all = "lowercase")]
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
}

impl ServiceId {
    pub fn new(name: impl Into<String>, namespace: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            namespace: namespace.into(),
        }
    }
}

// ============================================================================
// Connection Tracking Types
// ============================================================================

/// Unique identifier for a TCP connection.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ConnectionId {
    /// Unique connection ID (monotonically increasing).
    id: u64,
}

impl ConnectionId {
    fn new(id: u64) -> Self {
        Self { id }
    }
}

/// Statistics for a VIP allocation. All fields are atomic for lock-free updates.
/// This struct is shared between the VipManager actor and ActiveConnection guards,
/// allowing real-time stats updates without message passing.
pub struct VipStats {
    /// Number of currently active connections.
    pub active_connections: AtomicU32,
    /// Total number of connections ever made to this VIP.
    pub total_connections: AtomicU64,
    /// Total bytes sent through this VIP.
    pub bytes_sent: AtomicU64,
    /// Total bytes received through this VIP.
    pub bytes_received: AtomicU64,
}

impl VipStats {
    fn new() -> Self {
        Self {
            active_connections: AtomicU32::new(0),
            total_connections: AtomicU64::new(0),
            bytes_sent: AtomicU64::new(0),
            bytes_received: AtomicU64::new(0),
        }
    }

    /// Adds to the bytes sent counter.
    pub fn add_bytes_sent(&self, n: u64) {
        self.bytes_sent.fetch_add(n, Ordering::Relaxed);
    }

    /// Adds to the bytes received counter.
    pub fn add_bytes_received(&self, n: u64) {
        self.bytes_received.fetch_add(n, Ordering::Relaxed);
    }

    /// Returns a snapshot of the current stats.
    pub fn snapshot(&self) -> VipStatsSnapshot {
        VipStatsSnapshot {
            active_connections: self.active_connections.load(Ordering::Relaxed),
            total_connections: self.total_connections.load(Ordering::Relaxed),
            bytes_sent: self.bytes_sent.load(Ordering::Relaxed),
            bytes_received: self.bytes_received.load(Ordering::Relaxed),
        }
    }
}

impl Default for VipStats {
    fn default() -> Self {
        Self::new()
    }
}

/// A point-in-time snapshot of VIP statistics.
#[derive(Debug, Clone, Default, Serialize)]
pub struct VipStatsSnapshot {
    pub active_connections: u32,
    pub total_connections: u64,
    pub bytes_sent: u64,
    pub bytes_received: u64,
}

/// Information about an active connection to a VIP.
#[derive(Debug, Clone, Serialize)]
pub struct ConnectionInfo {
    /// When the connection was created (RFC3339 format).
    pub created_at: DateTime<Utc>,
    /// Source IP address (who initiated the connection).
    pub src_ip: Ipv4Addr,
    /// Source port.
    pub src_port: u16,
    /// Destination port.
    pub dst_port: u16,
}

/// Detailed information about a VIP allocation.
#[derive(Debug, Clone, Serialize)]
pub struct VipAllocation {
    /// The virtual IP address.
    pub vip: Ipv4Addr,
    /// The target (service or pod) this VIP maps to.
    pub target: TargetId,
    /// When this VIP was allocated (RFC3339 format).
    pub allocated_at: DateTime<Utc>,
    /// Current statistics for this VIP.
    pub stats: VipStatsSnapshot,
    /// Currently active connections to this VIP.
    pub connections: Vec<ConnectionInfo>,
}

// ============================================================================
// VIP Update Events (for real-time notifications)
// ============================================================================

/// Type of connection event.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ConnectionEventType {
    Connected,
    Disconnected,
}

/// Represents a state change in the VIP manager.
/// These events are broadcast to subscribers for real-time updates.
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "event", rename_all = "snake_case")]
pub enum VipUpdate {
    /// A new VIP was allocated for a target.
    VipAllocated { vip: Ipv4Addr, target: TargetId },
    /// A VIP was removed (due to stale cleanup).
    VipRemoved { vip: Ipv4Addr, target: TargetId },
    /// Connection count changed for a VIP.
    ConnectionChanged {
        vip: Ipv4Addr,
        event_type: ConnectionEventType,
        connection: ConnectionInfo,
        active_connections: u32,
        total_connections: u64,
    },
}

// ============================================================================
// RAII Connection Guard
// ============================================================================

/// RAII guard for an active connection.
///
/// When this guard is dropped, it automatically:
/// - Decrements the active connection count
/// - Notifies the VipManager actor to update last_activity timestamp
///
/// Stats updates (bytes sent/received) are immediately visible to VipManager
/// since they share the same `Arc<VipStats>`.
pub struct ActiveConnection {
    vip: Ipv4Addr,
    conn_id: ConnectionId,
    sender: mpsc::Sender<VipMessage>,
    stats: Arc<VipStats>,
}

impl ActiveConnection {

    /// Adds to the bytes sent counter. Updates are immediately visible to VipManager.
    pub fn add_bytes_sent(&self, n: u64) {
        self.stats.add_bytes_sent(n);
    }

    /// Adds to the bytes received counter. Updates are immediately visible to VipManager.
    pub fn add_bytes_received(&self, n: u64) {
        self.stats.add_bytes_received(n);
    }
}

impl Drop for ActiveConnection {
    fn drop(&mut self) {
        // Decrement active connection count atomically
        self.stats
            .active_connections
            .fetch_sub(1, Ordering::Relaxed);

        // Notify actor to update last_activity timestamp
        let _ = self.sender.try_send(VipMessage::ConnectionClosed {
            vip: self.vip,
            conn_id: self.conn_id.clone(),
        });

        debug!("ActiveConnection dropped for VIP {}", self.vip);
    }
}

// ============================================================================
// Actor Messages
// ============================================================================

enum VipMessage {
    // Allocation (request/response)
    GetOrAllocateVip {
        target: TargetId,
        response: oneshot::Sender<Result<Ipv4Addr>>,
    },

    // Lookups (request/response)
    LookupTarget {
        vip: Ipv4Addr,
        response: oneshot::Sender<Option<TargetId>>,
    },

    // Connection registration (request/response - returns Arc<VipStats> for the guard)
    RegisterConnection {
        vip: Ipv4Addr,
        src_addr: SocketAddr,
        dst_port: u16,
        response: oneshot::Sender<Option<(ConnectionId, Arc<VipStats>)>>,
    },

    // Connection tracking (fire-and-forget)
    ConnectionClosed {
        vip: Ipv4Addr,
        conn_id: ConnectionId,
    },

    // Stats and inspection
    GetStats {
        vip: Ipv4Addr,
        response: oneshot::Sender<Option<VipStatsSnapshot>>,
    },
    GetAllMappings {
        response: oneshot::Sender<Vec<(Ipv4Addr, ServiceId)>>,
    },
    GetAllTargetMappings {
        response: oneshot::Sender<Vec<VipAllocation>>,
    },
}

// ============================================================================
// Actor Internal State
// ============================================================================

/// Internal tracking data for an active connection.
struct ConnectionEntry {
    created_at: DateTime<Utc>,
    src_ip: Ipv4Addr,
    src_port: u16,
    dst_port: u16,
}

/// Per-VIP allocation entry.
struct VipEntry {
    target: TargetId,
    active_connections: HashMap<ConnectionId, ConnectionEntry>,
    allocated_at: DateTime<Utc>,
    last_activity: Instant,
    stats: Arc<VipStats>,
}

/// Entry in the stale-tracking heap.
#[derive(Eq, PartialEq)]
struct HeapEntry {
    last_activity: Reverse<Instant>,
    vip: Ipv4Addr,
}

impl Ord for HeapEntry {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.last_activity.cmp(&other.last_activity)
    }
}

impl PartialOrd for HeapEntry {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

/// The VIP manager actor that owns all state.
struct VipManagerActor {
    base_ip: Ipv4Addr,
    next_offset: u32,
    max_ips: u32,

    /// VIP -> entry mapping.
    vip_entries: HashMap<Ipv4Addr, VipEntry>,
    /// Reverse lookup: target -> VIP.
    target_to_vip: HashMap<TargetId, Ipv4Addr>,

    /// Recycled VIPs available for reuse.
    free_vips: Vec<Ipv4Addr>,

    /// Min-heap for stale entry cleanup (oldest first).
    stale_heap: BinaryHeap<HeapEntry>,

    /// Next connection ID.
    next_conn_id: u64,

    /// Message receiver.
    receiver: mpsc::Receiver<VipMessage>,

    /// Broadcast sender for real-time updates.
    update_tx: broadcast::Sender<VipUpdate>,

    /// Stale timeout duration.
    stale_timeout: Duration,

    /// Cleanup check interval.
    cleanup_interval: Duration,
}

impl VipManagerActor {
    async fn run(mut self) {
        let mut cleanup_ticker = tokio::time::interval(self.cleanup_interval);

        loop {
            tokio::select! {
                biased;

                // Handle incoming messages
                Some(msg) = self.receiver.recv() => {
                    self.handle_message(msg);
                }

                // Periodic cleanup
                _ = cleanup_ticker.tick() => {
                    self.cleanup_stale_entries();
                }

                else => break,
            }
        }

        info!("VipManager actor shutting down");
    }

    fn handle_message(&mut self, msg: VipMessage) {
        match msg {
            VipMessage::GetOrAllocateVip { target, response } => {
                let result = self.get_or_allocate_vip(target);
                let _ = response.send(result);
            }

            VipMessage::LookupTarget { vip, response } => {
                let target = self.vip_entries.get(&vip).map(|e| e.target.clone());
                let _ = response.send(target);
            }

            VipMessage::RegisterConnection {
                vip,
                src_addr,
                dst_port,
                response,
            } => {
                let result = self.register_connection(vip, src_addr, dst_port);
                let _ = response.send(result);
            }

            VipMessage::ConnectionClosed { vip, conn_id } => {
                self.handle_connection_closed(vip, conn_id);
            }

            VipMessage::GetStats { vip, response } => {
                let stats = self.vip_entries.get(&vip).map(|e| e.stats.snapshot());
                let _ = response.send(stats);
            }

            VipMessage::GetAllMappings { response } => {
                let mappings = self
                    .vip_entries
                    .iter()
                    .filter_map(|(vip, entry)| {
                        if let TargetId::Service(svc) = &entry.target {
                            Some((*vip, svc.clone()))
                        } else {
                            None
                        }
                    })
                    .collect();
                let _ = response.send(mappings);
            }

            VipMessage::GetAllTargetMappings { response } => {
                let mappings = self
                    .vip_entries
                    .iter()
                    .map(|(vip, entry)| {
                        let connections = entry
                            .active_connections
                            .values()
                            .map(|conn| ConnectionInfo {
                                created_at: conn.created_at,
                                src_ip: conn.src_ip,
                                src_port: conn.src_port,
                                dst_port: conn.dst_port,
                            })
                            .collect();
                        VipAllocation {
                            vip: *vip,
                            target: entry.target.clone(),
                            allocated_at: entry.allocated_at,
                            stats: entry.stats.snapshot(),
                            connections,
                        }
                    })
                    .collect();
                let _ = response.send(mappings);
            }
        }
    }

    fn get_or_allocate_vip(&mut self, target: TargetId) -> Result<Ipv4Addr> {
        // Check if target already has a VIP
        if let Some(&vip) = self.target_to_vip.get(&target) {
            // Update last activity on lookup
            let now = Instant::now();
            if let Some(entry) = self.vip_entries.get_mut(&vip) {
                entry.last_activity = now;
            }
            // Push to heap after releasing borrow
            self.stale_heap.push(HeapEntry {
                last_activity: Reverse(now),
                vip,
            });
            debug!("Returning existing VIP {} for {:?}", vip, target);
            return Ok(vip);
        }

        // Allocate new VIP (prefer recycled)
        let vip = self.allocate_next_vip()?;

        let now = Instant::now();
        let stats = Arc::new(VipStats::new());

        self.vip_entries.insert(
            vip,
            VipEntry {
                target: target.clone(),
                active_connections: HashMap::new(),
                allocated_at: Utc::now(),
                last_activity: now,
                stats,
            },
        );
        self.target_to_vip.insert(target.clone(), vip);

        // Add to stale heap
        self.stale_heap.push(HeapEntry {
            last_activity: Reverse(now),
            vip,
        });

        // Broadcast the allocation
        let _ = self.update_tx.send(VipUpdate::VipAllocated {
            vip,
            target: target.clone(),
        });

        info!("Allocated VIP {} for {:?}", vip, target);
        Ok(vip)
    }

    fn allocate_next_vip(&mut self) -> Result<Ipv4Addr> {
        // Try to reuse a recycled VIP first
        if let Some(vip) = self.free_vips.pop() {
            debug!("Recycling VIP {}", vip);
            return Ok(vip);
        }

        // Allocate new
        if self.next_offset >= self.max_ips {
            return Err(anyhow!("VIP pool exhausted"));
        }

        let vip = Ipv4Addr::from(u32::from(self.base_ip) + self.next_offset);
        self.next_offset += 1;

        Ok(vip)
    }

    fn register_connection(
        &mut self,
        vip: Ipv4Addr,
        src_addr: SocketAddr,
        dst_port: u16,
    ) -> Option<(ConnectionId, Arc<VipStats>)> {
        let conn_id = ConnectionId::new(self.next_conn_id);
        self.next_conn_id += 1;

        // Extract IPv4 address from SocketAddr
        let src_ip = match src_addr {
            SocketAddr::V4(addr) => *addr.ip(),
            SocketAddr::V6(_) => return None, // IPv6 not supported
        };

        let now = Instant::now();
        let created_at = Utc::now();
        let (stats, active, total) = {
            let entry = self.vip_entries.get_mut(&vip)?;

            // Update stats
            let active = entry
                .stats
                .active_connections
                .fetch_add(1, Ordering::Relaxed)
                + 1;
            let total = entry
                .stats
                .total_connections
                .fetch_add(1, Ordering::Relaxed)
                + 1;

            // Track connection with metadata
            let conn_entry = ConnectionEntry {
                created_at,
                src_ip,
                src_port: src_addr.port(),
                dst_port,
            };
            entry.active_connections.insert(conn_id.clone(), conn_entry);
            entry.last_activity = now;

            (Arc::clone(&entry.stats), active, total)
        };

        // Push to heap after releasing borrow
        self.stale_heap.push(HeapEntry {
            last_activity: Reverse(now),
            vip,
        });

        // Broadcast the connection change with details
        let connection = ConnectionInfo {
            created_at,
            src_ip,
            src_port: src_addr.port(),
            dst_port,
        };
        let _ = self.update_tx.send(VipUpdate::ConnectionChanged {
            vip,
            event_type: ConnectionEventType::Connected,
            connection,
            active_connections: active,
            total_connections: total,
        });

        debug!("Registered connection {:?} for VIP {}", conn_id, vip);

        Some((conn_id, stats))
    }

    fn handle_connection_closed(&mut self, vip: Ipv4Addr, conn_id: ConnectionId) {
        let now = Instant::now();
        let connection_data = {
            if let Some(entry) = self.vip_entries.get_mut(&vip) {
                // Get connection info before removing
                let conn_info =
                    entry
                        .active_connections
                        .remove(&conn_id)
                        .map(|conn| ConnectionInfo {
                            created_at: conn.created_at,
                            src_ip: conn.src_ip,
                            src_port: conn.src_port,
                            dst_port: conn.dst_port,
                        });
                entry.last_activity = now;
                let active = entry.stats.active_connections.load(Ordering::Relaxed);
                let total = entry.stats.total_connections.load(Ordering::Relaxed);
                conn_info.map(|info| (entry.active_connections.len(), active, total, info))
            } else {
                None
            }
        };

        if let Some((count, active, total, connection)) = connection_data {
            // Push to heap after releasing borrow
            self.stale_heap.push(HeapEntry {
                last_activity: Reverse(now),
                vip,
            });

            // Broadcast the connection change with details
            let _ = self.update_tx.send(VipUpdate::ConnectionChanged {
                vip,
                event_type: ConnectionEventType::Disconnected,
                connection,
                active_connections: active,
                total_connections: total,
            });

            debug!(
                "Connection {:?} closed for VIP {} ({} active)",
                conn_id, vip, count
            );
        }
    }

    fn cleanup_stale_entries(&mut self) {
        let now = Instant::now();
        let mut removed_count = 0;

        while let Some(heap_entry) = self.stale_heap.peek() {
            let vip = heap_entry.vip;

            // Check if this heap entry is stale (outdated timestamp)
            let Some(entry) = self.vip_entries.get(&vip) else {
                // VIP no longer exists, remove from heap
                self.stale_heap.pop();
                continue;
            };

            // Check if heap entry is outdated
            if entry.last_activity != heap_entry.last_activity.0 {
                // Outdated heap entry, remove it
                self.stale_heap.pop();
                continue;
            }

            // Check if it's actually stale
            let idle_duration = now.duration_since(entry.last_activity);
            if idle_duration < self.stale_timeout {
                // Not stale yet, stop processing (heap is ordered by oldest first)
                break;
            }

            // Check if there are active connections
            if !entry.active_connections.is_empty() {
                // Has active connections, can't remove. Update timestamp and re-add to heap.
                self.stale_heap.pop();
                // Entry will be re-added when a connection closes
                continue;
            }

            // Remove the stale entry
            self.stale_heap.pop();
            let target = entry.target.clone();
            self.vip_entries.remove(&vip);
            self.target_to_vip.remove(&target);

            // Recycle the VIP
            self.free_vips.push(vip);

            // Broadcast the removal
            let _ = self.update_tx.send(VipUpdate::VipRemoved {
                vip,
                target: target.clone(),
            });

            removed_count += 1;
            info!(
                "Removed stale VIP {} for {:?} (idle {:?})",
                vip, target, idle_duration
            );
        }

        if removed_count > 0 {
            info!("Cleanup: removed {} stale VIP allocations", removed_count);
        }
    }
}

// ============================================================================
// VipManager Handle (Public API)
// ============================================================================

/// Configuration for the VIP manager.
pub struct VipManagerConfig {
    /// Base IP address for the VIP pool (e.g., 198.18.0.0).
    pub base_ip: Ipv4Addr,
    /// Timeout after which idle VIPs (no active connections) are removed.
    pub stale_timeout: Duration,
    /// How often to check for stale entries.
    pub cleanup_interval: Duration,
}

impl Default for VipManagerConfig {
    fn default() -> Self {
        Self {
            base_ip: Ipv4Addr::new(198, 18, 0, 0),
            stale_timeout: Duration::from_secs(600), // 10 minutes
            cleanup_interval: Duration::from_secs(60), // 1 minute
        }
    }
}

/// Handle to the VIP manager actor.
///
/// This handle is cheaply cloneable and can be shared across tasks.
/// All operations are thread-safe and use message passing internally.
#[derive(Clone)]
pub struct VipManager {
    sender: mpsc::Sender<VipMessage>,
    update_tx: broadcast::Sender<VipUpdate>,
    base_ip: Ipv4Addr,
    max_ips: u32,
}
#[allow(dead_code)]
impl VipManager {
    /// Creates a new VIP manager with the given base IP and default configuration.
    pub fn new(base_ip: Ipv4Addr) -> Self {
        Self::with_config(VipManagerConfig {
            base_ip,
            ..Default::default()
        })
    }

    /// Creates a new VIP manager with the given base IP and stale timeout.
    pub fn with_stale_timeout(base_ip: Ipv4Addr, stale_timeout: Duration) -> Self {
        Self::with_config(VipManagerConfig {
            base_ip,
            stale_timeout,
            ..Default::default()
        })
    }

    /// Creates a new VIP manager with full configuration.
    pub fn with_config(config: VipManagerConfig) -> Self {
        let (sender, receiver) = mpsc::channel(256);
        let (update_tx, _) = broadcast::channel(256);

        let actor = VipManagerActor {
            base_ip: config.base_ip,
            next_offset: 2, // Skip .0 (network) and .1 (gateway)
            max_ips: 65534,
            vip_entries: HashMap::new(),
            target_to_vip: HashMap::new(),
            free_vips: Vec::new(),
            stale_heap: BinaryHeap::new(),
            next_conn_id: 1,
            receiver,
            update_tx: update_tx.clone(),
            stale_timeout: config.stale_timeout,
            cleanup_interval: config.cleanup_interval,
        };

        info!(
            "Starting VIP manager actor with base IP: {}",
            config.base_ip
        );
        tokio::spawn(actor.run());

        Self {
            sender,
            update_tx,
            base_ip: config.base_ip,
            max_ips: 65534,
        }
    }

    /// Allocates or retrieves a VIP for the given target (service or pod).
    pub async fn get_or_allocate_vip_for_target(&self, target: TargetId) -> Result<Ipv4Addr> {
        let (tx, rx) = oneshot::channel();
        self.sender
            .send(VipMessage::GetOrAllocateVip {
                target,
                response: tx,
            })
            .await
            .map_err(|_| anyhow!("VipManager actor died"))?;
        rx.await.map_err(|_| anyhow!("VipManager actor died"))?
    }

    /// Looks up the target (service or pod) associated with a VIP.
    pub async fn lookup_target(&self, vip: Ipv4Addr) -> Option<TargetId> {
        let (tx, rx) = oneshot::channel();
        self.sender
            .send(VipMessage::LookupTarget { vip, response: tx })
            .await
            .ok()?;
        rx.await.ok()?
    }

    /// Looks up the service associated with a VIP.
    pub async fn lookup_service(&self, vip: Ipv4Addr) -> Option<ServiceId> {
        self.lookup_target(vip).await.and_then(|t| match t {
            TargetId::Service(s) => Some(s),
            TargetId::Pod(_) => None,
        })
    }

    /// Looks up the pod associated with a VIP.
    pub async fn lookup_pod(&self, vip: Ipv4Addr) -> Option<PodId> {
        self.lookup_target(vip).await.and_then(|t| match t {
            TargetId::Pod(p) => Some(p),
            TargetId::Service(_) => None,
        })
    }

    /// Looks up the VIP associated with a service.
    pub async fn lookup_vip(&self, service: &ServiceId) -> Option<Ipv4Addr> {
        // This is a workaround - we allocate to get/lookup
        // In a production system, you'd add a dedicated lookup message
        self.get_or_allocate_vip_for_target(TargetId::Service(service.clone())).await.ok()
    }

    /// Looks up the VIP associated with a pod.
    pub async fn lookup_vip_for_pod(&self, pod: &PodId) -> Option<Ipv4Addr> {
        self.get_or_allocate_vip_for_target(TargetId::Pod(pod.clone())).await.ok()
    }

    /// Registers a new connection to the given VIP.
    ///
    /// Returns an `ActiveConnection` guard that automatically unregisters
    /// when dropped. The guard provides methods to update byte counters.
    ///
    /// # Arguments
    /// * `vip` - The VIP address being connected to
    /// * `src_addr` - The source address of the connection (for tracking)
    /// * `dst_port` - The destination port of the connection
    pub async fn register_connection(
        &self,
        vip: Ipv4Addr,
        src_addr: SocketAddr,
        dst_port: u16,
    ) -> Option<ActiveConnection> {
        let (tx, rx) = oneshot::channel();
        self.sender
            .send(VipMessage::RegisterConnection {
                vip,
                src_addr,
                dst_port,
                response: tx,
            })
            .await
            .ok()?;

        let (conn_id, stats) = rx.await.ok()??;

        Some(ActiveConnection {
            vip,
            conn_id,
            sender: self.sender.clone(),
            stats,
        })
    }

    /// Checks if an IP address is within the VIP pool range.
    pub fn is_vip(&self, ip: Ipv4Addr) -> bool {
        let base_u32 = u32::from(self.base_ip);
        let ip_u32 = u32::from(ip);
        ip_u32 >= base_u32 && ip_u32 < base_u32 + self.max_ips
    }

    /// Returns all currently allocated VIP mappings for services.
    pub async fn get_all_mappings(&self) -> Vec<(Ipv4Addr, ServiceId)> {
        let (tx, rx) = oneshot::channel();
        if self
            .sender
            .send(VipMessage::GetAllMappings { response: tx })
            .await
            .is_err()
        {
            return Vec::new();
        }
        rx.await.unwrap_or_default()
    }

    /// Returns all currently allocated VIP mappings with detailed info.
    pub async fn get_all_target_mappings(&self) -> Vec<VipAllocation> {
        let (tx, rx) = oneshot::channel();
        if self
            .sender
            .send(VipMessage::GetAllTargetMappings { response: tx })
            .await
            .is_err()
        {
            return Vec::new();
        }
        rx.await.unwrap_or_default()
    }

    /// Gets stats for a specific VIP.
    pub async fn get_stats(&self, vip: Ipv4Addr) -> Option<VipStatsSnapshot> {
        let (tx, rx) = oneshot::channel();
        self.sender
            .send(VipMessage::GetStats { vip, response: tx })
            .await
            .ok()?;
        rx.await.ok()?
    }

    /// Pre-allocates VIPs for a list of services.
    pub async fn pre_allocate(&self, services: Vec<ServiceId>) -> Result<()> {
        for service in services {
            self.get_or_allocate_vip_for_target(TargetId::Service(service)).await?;
        }
        Ok(())
    }

    /// Subscribes to real-time VIP updates.
    ///
    /// Returns a broadcast receiver that will receive `VipUpdate` events
    /// whenever the VIP state changes (allocations, removals, connection changes).
    pub fn subscribe(&self) -> broadcast::Receiver<VipUpdate> {
        self.update_tx.subscribe()
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_target_id() {
        let svc = ServiceId::new("backend", "default");
        let pod = PodId::new("mysql-0", "default");

        let target_svc = TargetId::Service(svc.clone());
        let target_pod = TargetId::Pod(pod.clone());

        assert!(matches!(target_svc, TargetId::Service(_)));
        assert_eq!(target_svc.name(), "backend");
        assert_eq!(target_svc.namespace(), "default");

        assert!(matches!(target_pod, TargetId::Pod(_)));

        assert_eq!(target_pod.name(), "mysql-0");
        assert_eq!(target_pod.namespace(), "default");
    }

    #[tokio::test]
    async fn test_vip_allocation() {
        let manager = VipManager::new(Ipv4Addr::new(198, 18, 0, 0));

        let svc1 = ServiceId::new("svc1", "default");
        let svc2 = ServiceId::new("svc2", "default");

        let vip1 = manager.get_or_allocate_vip_for_target(TargetId::Service(svc1.clone())).await.unwrap();
        let vip2 = manager.get_or_allocate_vip_for_target(TargetId::Service(svc2.clone())).await.unwrap();

        // Should get different VIPs
        assert_ne!(vip1, vip2);

        // First VIP should be .2 (skipping .0 and .1)
        assert_eq!(vip1, Ipv4Addr::new(198, 18, 0, 2));
        assert_eq!(vip2, Ipv4Addr::new(198, 18, 0, 3));

        // Same service should return same VIP
        let vip1_again = manager.get_or_allocate_vip_for_target(TargetId::Service(svc1)).await.unwrap();
        assert_eq!(vip1, vip1_again);
    }

    #[tokio::test]
    async fn test_pod_vip_allocation() {
        let manager = VipManager::new(Ipv4Addr::new(198, 18, 0, 0));

        let pod1 = PodId::new("mysql-0", "default");
        let pod2 = PodId::new("mysql-1", "default");

        let vip1 = manager
            .get_or_allocate_vip_for_target(TargetId::Pod(pod1.clone()))
            .await
            .unwrap();
        let vip2 = manager
            .get_or_allocate_vip_for_target(TargetId::Pod(pod2.clone()))
            .await
            .unwrap();

        // Should get different VIPs
        assert_ne!(vip1, vip2);

        // Same pod should return same VIP
        let vip1_again = manager
            .get_or_allocate_vip_for_target(TargetId::Pod(pod1.clone()))
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

        let svc = ServiceId::new("mysql", "default");
        let pod = PodId::new("mysql-0", "default");

        let svc_vip = manager.get_or_allocate_vip_for_target(TargetId::Service(svc.clone())).await.unwrap();
        let pod_vip = manager
            .get_or_allocate_vip_for_target(TargetId::Pod(pod.clone()))
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

    #[tokio::test]
    async fn test_is_vip() {
        let manager = VipManager::new(Ipv4Addr::new(198, 18, 0, 0));

        assert!(manager.is_vip(Ipv4Addr::new(198, 18, 0, 1)));
        assert!(manager.is_vip(Ipv4Addr::new(198, 18, 255, 253)));
        assert!(!manager.is_vip(Ipv4Addr::new(198, 19, 0, 0)));
        assert!(!manager.is_vip(Ipv4Addr::new(192, 168, 1, 1)));
    }

    #[tokio::test]
    async fn test_connection_tracking() {
        use std::net::SocketAddrV4;

        let manager = VipManager::new(Ipv4Addr::new(198, 18, 0, 0));

        let svc = ServiceId::new("test-svc", "default");
        let vip = manager.get_or_allocate_vip_for_target(TargetId::Service(svc)).await.unwrap();

        // Create test source addresses
        let src1 = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(192, 168, 1, 100), 12345));
        let src2 = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(192, 168, 1, 101), 12346));
        let dst_port = 8080;

        // Register a connection
        let conn = manager
            .register_connection(vip, src1, dst_port)
            .await
            .unwrap();

        // Check stats
        let stats = manager.get_stats(vip).await.unwrap();
        assert_eq!(stats.active_connections, 1);
        assert_eq!(stats.total_connections, 1);

        // Update bytes
        conn.add_bytes_sent(100);
        conn.add_bytes_received(200);

        // Check updated stats
        let stats = manager.get_stats(vip).await.unwrap();
        assert_eq!(stats.bytes_sent, 100);
        assert_eq!(stats.bytes_received, 200);

        // Register another connection
        let conn2 = manager
            .register_connection(vip, src2, dst_port)
            .await
            .unwrap();
        let stats = manager.get_stats(vip).await.unwrap();
        assert_eq!(stats.active_connections, 2);
        assert_eq!(stats.total_connections, 2);

        // Drop first connection
        drop(conn);

        // Give actor time to process
        tokio::time::sleep(Duration::from_millis(10)).await;

        let stats = manager.get_stats(vip).await.unwrap();
        assert_eq!(stats.active_connections, 1);

        // Drop second connection
        drop(conn2);
        tokio::time::sleep(Duration::from_millis(10)).await;

        let stats = manager.get_stats(vip).await.unwrap();
        assert_eq!(stats.active_connections, 0);
    }

    #[tokio::test]
    async fn test_vip_recycling() {
        // Use very short timeout for testing
        let manager = VipManager::with_config(VipManagerConfig {
            base_ip: Ipv4Addr::new(198, 18, 0, 0),
            stale_timeout: Duration::from_millis(50),
            cleanup_interval: Duration::from_millis(25),
        });

        let svc1 = ServiceId::new("svc1", "default");
        let vip1 = manager.get_or_allocate_vip_for_target(TargetId::Service(svc1)).await.unwrap();
        assert_eq!(vip1, Ipv4Addr::new(198, 18, 0, 2));

        // Wait for cleanup
        tokio::time::sleep(Duration::from_millis(100)).await;

        // VIP should be recycled, next allocation should get same VIP
        let svc2 = ServiceId::new("svc2", "default");
        let vip2 = manager.get_or_allocate_vip_for_target(TargetId::Service(svc2)).await.unwrap();
        assert_eq!(vip2, Ipv4Addr::new(198, 18, 0, 2)); // Recycled!
    }
}
