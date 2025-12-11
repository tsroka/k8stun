//! Userspace TCP/IP stack integration using lwIP.
//!
//! This module wraps the lwip crate to provide TCP connection handling
//! in userspace, allowing us to terminate connections locally.

#![allow(dead_code)]

use anyhow::Result;
use futures::{SinkExt, StreamExt};
use lwip::{NetStack, TcpListener, UdpSocket};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::mpsc;
use tracing::{debug, error, info, trace, warn};
use tun2::AsyncDevice;

use crate::dns_resolver::DnsResolver;
use crate::vip::{ServiceId, VipManager};

/// A TCP stream from the userspace stack.
pub struct TcpStream {
    inner: lwip::TcpStream,
    pub local_addr: SocketAddr,
    pub peer_addr: SocketAddr,
}

impl TcpStream {
    pub fn into_split(self) -> (impl AsyncRead, impl AsyncWrite) {
        tokio::io::split(self.inner)
    }

    pub fn inner_mut(&mut self) -> &mut lwip::TcpStream {
        &mut self.inner
    }
}

impl AsyncRead for TcpStream {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl AsyncWrite for TcpStream {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        std::pin::Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

/// Information about an accepted TCP connection.
pub struct AcceptedConnection {
    pub stream: TcpStream,
    pub service: ServiceId,
}

/// The userspace network stack that handles TCP connections.
pub struct NetworkStack {
    vip_manager: Arc<VipManager>,
    /// Channel to receive accepted TCP connections.
    connection_rx: mpsc::Receiver<AcceptedConnection>,
}

impl NetworkStack {
    /// Creates a new network stack using the given TUN device.
    pub async fn new(
        device: AsyncDevice,
        vip_manager: Arc<VipManager>,
        dns_resolver: Option<Arc<DnsResolver>>,
    ) -> Result<Self> {
        let (connection_tx, connection_rx) = mpsc::channel(64);

        // Build the lwIP stack with TCP and UDP support
        let (stack, tcp_listener, udp_socket) =
            NetStack::new().map_err(|e| anyhow::anyhow!("Failed to build network stack: {}", e))?;

        // Spawn the packet processing task (TUN <-> Stack)
        tokio::spawn(run_tun_stack_bridge(device, stack));

        // Spawn the TCP connection handling task
        let vip_manager_clone = Arc::clone(&vip_manager);
        tokio::spawn(async move {
            if let Err(e) = run_tcp_listener(tcp_listener, vip_manager_clone, connection_tx).await {
                error!("TCP listener error: {}", e);
            }
        });

        // Spawn the UDP/DNS handling task
        if let Some(resolver) = dns_resolver {
            info!("DNS resolver enabled");
            tokio::spawn(async move {
                if let Err(e) = run_udp_handler(udp_socket, resolver).await {
                    error!("UDP handler error: {}", e);
                }
            });
        } else {
            info!("DNS resolver not configured, UDP packets will not be handled");
        }

        info!("Network stack started, waiting for connections...");

        Ok(Self {
            vip_manager,
            connection_rx,
        })
    }

    /// Accepts the next TCP connection from the stack.
    pub async fn accept(&mut self) -> Option<AcceptedConnection> {
        self.connection_rx.recv().await
    }
}

/// Bridge between TUN device and the lwIP NetStack.
/// Reads packets from TUN and sends to Stack, reads from Stack and sends to TUN.
async fn run_tun_stack_bridge(device: AsyncDevice, stack: NetStack) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let (mut tun_reader, mut tun_writer) = tokio::io::split(device);
    let (mut stack_sink, mut stack_stream) = stack.split();

    // Task: TUN -> Stack
    let tun_to_stack = async {
        let mut buf = vec![0u8; 65535];
        loop {
            match tun_reader.read(&mut buf).await {
                Ok(0) => {
                    trace!("TUN read returned 0 bytes, EOF");
                    break;
                }
                Ok(n) => {
                    let packet = buf[..n].to_vec();
                    if let Err(e) = stack_sink.send(packet).await {
                        error!("Failed to send packet to stack: {}", e);
                        break;
                    }
                }
                Err(e) => {
                    error!("TUN read error: {}", e);
                    break;
                }
            }
        }
    };

    // Task: Stack -> TUN
    let stack_to_tun = async {
        while let Some(result) = stack_stream.next().await {
            match result {
                Ok(packet) => {
                    if let Err(e) = tun_writer.write_all(&packet).await {
                        error!("TUN write error: {}", e);
                        break;
                    }
                }
                Err(e) => {
                    error!("Stack read error: {}", e);
                    break;
                }
            }
        }
    };

    tokio::select! {
        _ = tun_to_stack => {
            trace!("TUN->Stack task ended");
        }
        _ = stack_to_tun => {
            trace!("Stack->TUN task ended");
        }
    }
}

/// Main loop that accepts TCP connections from the TCP listener.
async fn run_tcp_listener(
    mut tcp_listener: TcpListener,
    vip_manager: Arc<VipManager>,
    connection_tx: mpsc::Sender<AcceptedConnection>,
) -> Result<()> {
    // TcpListener is a Stream that yields (TcpStream, local_addr, remote_addr)
    while let Some((tcp_stream, local_addr, peer_addr)) = tcp_listener.next().await {
        debug!("TCP connection: {} -> {}", local_addr, peer_addr);

        // Look up the service for this VIP
        let dst_ip = match peer_addr {
            SocketAddr::V4(addr) => *addr.ip(),
            SocketAddr::V6(_) => {
                warn!("IPv6 not supported, refusing connection");
                // lwip's TcpStream sends RST on drop if not closed, so just drop it
                drop(tcp_stream);
                continue;
            }
        };

        let dst_port = peer_addr.port();

        // Check if this is a VIP
        if !vip_manager.is_vip(dst_ip) {
            debug!("Destination {} is not a VIP, refusing connection", dst_ip);
            // lwip's TcpStream sends RST on drop if not closed, so just drop it
            drop(tcp_stream);
            continue;
        }

        // Look up the service
        let service = match vip_manager.lookup_service(dst_ip).await {
            Some(mut svc) => {
                // Update the port to the connection port
                svc.port = dst_port;
                svc
            }
            None => {
                warn!("No service found for VIP {}, refusing connection", dst_ip);
                // lwip's TcpStream sends RST on drop if not closed, so just drop it
                drop(tcp_stream);
                continue;
            }
        };

        let stream = TcpStream {
            inner: tcp_stream,
            local_addr,
            peer_addr,
        };

        let connection = AcceptedConnection { stream, service };

        if let Err(e) = connection_tx.send(connection).await {
            error!("Failed to send connection to handler: {}", e);
            break;
        }
    }

    Ok(())
}

/// Handles UDP packets, primarily for DNS resolution.
async fn run_udp_handler(udp_socket: Box<UdpSocket>, dns_resolver: Arc<DnsResolver>) -> Result<()> {
    let (udp_writer, mut udp_reader) = udp_socket.split();

    // Process incoming UDP packets
    while let Some((payload, src_addr, dst_addr)) = udp_reader.next().await {
        trace!("UDP packet: {} -> {}", src_addr, dst_addr);

        // Check if this is a DNS query (port 53)
        if dst_addr.port() == 53 {
            // Use the DnsResolver to handle the query
            match dns_resolver.resolve(&payload).await {
                Ok(Some(response)) => {
                    // Send response back: swap src and dst addresses
                    if let Err(e) = udp_writer.send_to(&response, &dst_addr, &src_addr) {
                        debug!("Failed to send DNS response: {}", e);
                    }
                }
                Ok(None) => {
                    // No response needed
                }
                Err(e) => {
                    debug!("DNS handling error: {}", e);
                }
            }
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_service_id_creation() {
        let service = ServiceId::new("backend", "default", 8080);
        assert_eq!(service.name, "backend");
        assert_eq!(service.namespace, "default");
        assert_eq!(service.port, 8080);
    }
}
