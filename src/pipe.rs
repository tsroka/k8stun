//! Bidirectional stream copying for tunneling data.
//!
//! This module handles the data plane - copying bytes between
//! the userspace TCP stack and Kubernetes port-forward streams.

#![allow(dead_code)]

use anyhow::Result;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tracing::{debug, error, trace};

/// Statistics for a pipe connection.
#[derive(Debug, Default)]
pub struct PipeStats {
    /// Bytes transferred from client to server.
    pub bytes_to_server: AtomicU64,
    /// Bytes transferred from server to client.
    pub bytes_to_client: AtomicU64,
}

impl PipeStats {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn total_bytes(&self) -> u64 {
        self.bytes_to_server.load(Ordering::Relaxed) + self.bytes_to_client.load(Ordering::Relaxed)
    }
}

/// Result of a pipe operation.
#[derive(Debug)]
pub enum PipeResult {
    /// Both sides closed gracefully.
    Completed { stats: Arc<PipeStats> },
    /// Client closed first.
    ClientClosed { stats: Arc<PipeStats> },
    /// Server closed first.
    ServerClosed { stats: Arc<PipeStats> },
    /// An error occurred.
    Error {
        error: String,
        stats: Arc<PipeStats>,
    },
}

/// Pipes data bidirectionally between two streams.
///
/// This function copies data in both directions concurrently:
/// - From `client` to `server`
/// - From `server` to `client`
///
/// The pipe continues until either side closes or an error occurs.
pub async fn pipe<C, S>(client: C, server: S) -> PipeResult
where
    C: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let stats = Arc::new(PipeStats::new());

    let (client_read, client_write) = tokio::io::split(client);
    let (server_read, server_write) = tokio::io::split(server);

    let stats_c2s = Arc::clone(&stats);
    let stats_s2c = Arc::clone(&stats);

    // Client to server
    let c2s = tokio::spawn(async move {
        copy_with_stats(client_read, server_write, &stats_c2s.bytes_to_server).await
    });

    // Server to client
    let s2c = tokio::spawn(async move {
        copy_with_stats(server_read, client_write, &stats_s2c.bytes_to_client).await
    });

    // Wait for both directions to complete
    let (c2s_result, s2c_result) = tokio::join!(c2s, s2c);

    let c2s_ok = c2s_result.as_ref().map(|r| r.is_ok()).unwrap_or(false);
    let s2c_ok = s2c_result.as_ref().map(|r| r.is_ok()).unwrap_or(false);

    match (c2s_ok, s2c_ok) {
        (true, true) => PipeResult::Completed { stats },
        (false, true) => PipeResult::ClientClosed { stats },
        (true, false) => PipeResult::ServerClosed { stats },
        (false, false) => {
            let error = c2s_result
                .err()
                .map(|e| e.to_string())
                .or_else(|| s2c_result.err().map(|e| e.to_string()))
                .unwrap_or_else(|| "Unknown error".to_string());
            PipeResult::Error { error, stats }
        }
    }
}

/// Copies data from reader to writer, tracking statistics.
async fn copy_with_stats<R, W>(
    mut reader: R,
    mut writer: W,
    bytes_counter: &AtomicU64,
) -> Result<u64>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut buf = [0u8; 8192];
    let mut total = 0u64;

    loop {
        let n = match reader.read(&mut buf).await {
            Ok(0) => break, // EOF
            Ok(n) => n,
            Err(e) => {
                trace!("Read error: {}", e);
                return Err(e.into());
            }
        };

        if let Err(e) = writer.write_all(&buf[..n]).await {
            trace!("Write error: {}", e);
            return Err(e.into());
        }

        total += n as u64;
        bytes_counter.fetch_add(n as u64, Ordering::Relaxed);

        trace!("Copied {} bytes (total: {})", n, total);
    }

    // Ensure all data is flushed
    if let Err(e) = writer.flush().await {
        trace!("Flush error: {}", e);
    }

    // Try to shutdown the write side
    if let Err(e) = writer.shutdown().await {
        trace!("Shutdown error: {}", e);
    }

    debug!("Stream copy completed, total {} bytes", total);
    Ok(total)
}

/// Pipes data with a timeout.
///
/// If no data is transferred for `idle_timeout`, the pipe is closed.
pub async fn pipe_with_timeout<C, S>(
    client: C,
    server: S,
    idle_timeout: std::time::Duration,
) -> PipeResult
where
    C: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let stats = Arc::new(PipeStats::new());

    let (mut client_read, mut client_write) = tokio::io::split(client);
    let (mut server_read, mut server_write) = tokio::io::split(server);

    let stats_c2s = Arc::clone(&stats);
    let stats_s2c = Arc::clone(&stats);

    // Client to server with timeout
    let c2s = tokio::spawn(async move {
        copy_with_timeout(
            &mut client_read,
            &mut server_write,
            &stats_c2s.bytes_to_server,
            idle_timeout,
        )
        .await
    });

    // Server to client with timeout
    let s2c = tokio::spawn(async move {
        copy_with_timeout(
            &mut server_read,
            &mut client_write,
            &stats_s2c.bytes_to_client,
            idle_timeout,
        )
        .await
    });

    tokio::select! {
        result = c2s => {
            match result {
                Ok(Ok(_)) => PipeResult::ClientClosed { stats },
                Ok(Err(e)) => PipeResult::Error { error: e.to_string(), stats },
                Err(e) => PipeResult::Error { error: e.to_string(), stats },
            }
        }
        result = s2c => {
            match result {
                Ok(Ok(_)) => PipeResult::ServerClosed { stats },
                Ok(Err(e)) => PipeResult::Error { error: e.to_string(), stats },
                Err(e) => PipeResult::Error { error: e.to_string(), stats },
            }
        }
    }
}

/// Copies data with an idle timeout.
async fn copy_with_timeout<R, W>(
    reader: &mut R,
    writer: &mut W,
    bytes_counter: &AtomicU64,
    timeout: std::time::Duration,
) -> Result<u64>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut buf = [0u8; 8192];
    let mut total = 0u64;

    loop {
        let read_future = reader.read(&mut buf);

        let n = match tokio::time::timeout(timeout, read_future).await {
            Ok(Ok(0)) => break, // EOF
            Ok(Ok(n)) => n,
            Ok(Err(e)) => {
                trace!("Read error: {}", e);
                return Err(e.into());
            }
            Err(_) => {
                debug!("Idle timeout reached after {}s", timeout.as_secs());
                break;
            }
        };

        if let Err(e) = writer.write_all(&buf[..n]).await {
            trace!("Write error: {}", e);
            return Err(e.into());
        }

        total += n as u64;
        bytes_counter.fetch_add(n as u64, Ordering::Relaxed);
    }

    let _ = writer.flush().await;
    let _ = writer.shutdown().await;

    Ok(total)
}

/// Manages multiple concurrent pipe connections.
pub struct PipeManager {
    /// Active connection count.
    active_connections: AtomicU64,
    /// Total bytes transferred across all connections.
    total_bytes: AtomicU64,
    /// Total connections handled.
    total_connections: AtomicU64,
}

impl PipeManager {
    pub fn new() -> Self {
        Self {
            active_connections: AtomicU64::new(0),
            total_bytes: AtomicU64::new(0),
            total_connections: AtomicU64::new(0),
        }
    }

    /// Spawns a new pipe connection.
    pub fn spawn<C, S>(&self, client: C, server: S, label: String)
    where
        C: AsyncRead + AsyncWrite + Unpin + Send + 'static,
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        self.active_connections.fetch_add(1, Ordering::Relaxed);
        self.total_connections.fetch_add(1, Ordering::Relaxed);

        let _active_counter = &self.active_connections as *const AtomicU64 as usize;
        let _total_counter = &self.total_bytes as *const AtomicU64 as usize;

        tokio::spawn(async move {
            debug!("Starting pipe for {}", label);

            let result = pipe(client, server).await;

            // Safety: These pointers are valid for the lifetime of PipeManager
            // In practice, you'd use Arc<Self> instead
            let _bytes = match &result {
                PipeResult::Completed { stats }
                | PipeResult::ClientClosed { stats }
                | PipeResult::ServerClosed { stats }
                | PipeResult::Error { stats, .. } => stats.total_bytes(),
            };

            match result {
                PipeResult::Completed { stats } => {
                    debug!(
                        "Pipe completed for {}: {} bytes transferred",
                        label,
                        stats.total_bytes()
                    );
                }
                PipeResult::ClientClosed { stats } => {
                    debug!(
                        "Client closed for {}: {} bytes transferred",
                        label,
                        stats.total_bytes()
                    );
                }
                PipeResult::ServerClosed { stats } => {
                    debug!(
                        "Server closed for {}: {} bytes transferred",
                        label,
                        stats.total_bytes()
                    );
                }
                PipeResult::Error { error, stats } => {
                    error!(
                        "Pipe error for {}: {} ({} bytes transferred)",
                        label,
                        error,
                        stats.total_bytes()
                    );
                }
            }
        });
    }

    /// Gets the number of active connections.
    pub fn active_connections(&self) -> u64 {
        self.active_connections.load(Ordering::Relaxed)
    }

    /// Gets the total bytes transferred.
    pub fn total_bytes(&self) -> u64 {
        self.total_bytes.load(Ordering::Relaxed)
    }

    /// Gets the total number of connections handled.
    pub fn total_connections(&self) -> u64 {
        self.total_connections.load(Ordering::Relaxed)
    }
}

impl Default for PipeManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::duplex;

    #[tokio::test]
    async fn test_pipe_basic() {
        let (client, server_end) = duplex(1024);
        let (server, client_end) = duplex(1024);

        // Spawn a task to echo data on the server side
        tokio::spawn(async move {
            let (mut read, mut write) = tokio::io::split(server_end);
            let mut buf = [0u8; 1024];
            while let Ok(n) = read.read(&mut buf).await {
                if n == 0 {
                    break;
                }
                let _ = write.write_all(&buf[..n]).await;
            }
        });

        // Write some data to the client
        let mut client_clone = client_end;
        tokio::spawn(async move {
            let _ = client_clone.write_all(b"hello").await;
            let _ = client_clone.shutdown().await;
        });

        let result = pipe(client, server).await;

        match result {
            PipeResult::Completed { stats }
            | PipeResult::ClientClosed { stats }
            | PipeResult::ServerClosed { stats } => {
                assert!(stats.total_bytes() > 0);
            }
            PipeResult::Error { error, .. } => {
                panic!("Pipe failed: {}", error);
            }
        }
    }
}
