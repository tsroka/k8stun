//! Userspace TCP/IP stack integration using lwIP.
//!
//! This module wraps the lwip crate to provide TCP connection handling
//! in userspace, allowing us to terminate connections locally.

use anyhow::Result;
use futures::{SinkExt, StreamExt};
use lwip::{NetStack, TcpListener, UdpRecvHalf, UdpSendHalf};
use std::net::SocketAddr;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::mpsc;
use tracing::{debug, error, info, trace, warn};
use tun2::AsyncDevice;

/// A TCP stream from the userspace stack.
pub struct TcpStream {
    inner: lwip::TcpStream,
    pub local_addr: SocketAddr,
    pub peer_addr: SocketAddr,
}

pub struct UdpPacket {
    pub src_addr: SocketAddr,
    pub dst_addr: SocketAddr,
    pub payload: Vec<u8>,
}

#[allow(dead_code)]
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
    /// The destination  address.
    pub dst_ip: std::net::Ipv4Addr,
    /// The destination port from the intercepted connection.
    pub dst_port: u16,
}

/// The userspace network stack that handles TCP connections.
pub struct NetworkStack {
    /// Channel to receive accepted TCP connections.
    pub tcp_rx: mpsc::Receiver<AcceptedConnection>,
    /// Channel to receive accepted UDP packets.
    pub udp_received_rx: mpsc::Receiver<UdpPacket>,
    // Channel to send UDP packets
    pub udp_send_tx: mpsc::Sender<UdpPacket>,
}

impl NetworkStack {
    /// Creates a new network stack using the given TUN device.
    pub async fn new(device: AsyncDevice) -> Result<Self> {
        let (udp_received_tx, udp_received_rx) = mpsc::channel(64);
        let (udp_send_tx, udp_send_rx) = mpsc::channel(64);
        let (tcp_tx, tcp_rx) = mpsc::channel(64);

        // Build the lwIP stack with TCP and UDP support
        let (stack, tcp_listener, udp_socket) =
            NetStack::new().map_err(|e| anyhow::anyhow!("Failed to build network stack: {}", e))?;

        // Spawn the packet processing task (TUN <-> Stack)
        tokio::spawn(run_tun_stack_bridge(device, stack));

        // Spawn the TCP connection handling task
        tokio::spawn(async move {
            if let Err(e) = run_tcp_listener(tcp_listener, tcp_tx).await {
                error!("TCP listener error: {}", e);
            }
        });

        // Spawn the UDP/DNS handling task
        let (udp_writer, udp_reader) = udp_socket.split();

        tokio::spawn(async move {
            if let Err(e) = run_udp_rx_handler(udp_reader, udp_received_tx).await {
                error!("UDP handler error: {}", e);
            }
        });
        tokio::spawn(async move {
            if let Err(e) = run_udp_tx_handler(udp_writer, udp_send_rx).await {
                error!("UDP handler error: {}", e);
            }
        });

        info!("Network stack started, waiting for connections...");

        Ok(Self {
            tcp_rx,
            udp_received_rx,
            udp_send_tx,
        })
    }
    pub fn split(
        self,
    ) -> (
        mpsc::Receiver<AcceptedConnection>,
        mpsc::Sender<UdpPacket>,
        mpsc::Receiver<UdpPacket>,
    ) {
        (self.tcp_rx, self.udp_send_tx, self.udp_received_rx)
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
    connection_tx: mpsc::Sender<AcceptedConnection>,
) -> Result<()> {
    // TcpListener is a Stream that yields (TcpStream, local_addr, remote_addr)
    while let Some((tcp_stream, local_addr, peer_addr)) = tcp_listener.next().await {
        debug!("TCP connection: {} -> {}", local_addr, peer_addr);

        // Look up the target for this VIP
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

        let stream = TcpStream {
            inner: tcp_stream,
            local_addr,
            peer_addr,
        };

        let connection = AcceptedConnection {
            stream,
            dst_ip,
            dst_port,
        };

        if let Err(e) = connection_tx.send(connection).await {
            error!("Failed to send connection to handler: {}", e);
            break;
        }
    }
    warn!("TCP listener closed");
    Ok(())
}

/// Handles UDP packets, primarily for DNS resolution.
async fn run_udp_rx_handler(
    mut udp_reader: UdpRecvHalf,
    client_udp_receive_tx: mpsc::Sender<UdpPacket>,
) -> Result<()> {
    info!("UDP receive handler started...");

    // Process incoming UDP packets
    while let Some((payload, src_addr, dst_addr)) = udp_reader.next().await {
        trace!("UDP packet: {} -> {}", src_addr, dst_addr);
        let packet = UdpPacket {
            src_addr,
            dst_addr,
            payload,
        };
        if let Err(e) = client_udp_receive_tx.send(packet).await {
            error!("Failed to send connection to handler: {}", e);
            break;
        }
    }
    warn!("UDP receive handler closed");
    Ok(())
}

async fn run_udp_tx_handler(
    udp_writer: UdpSendHalf,
    mut udp_receive_rx: mpsc::Receiver<UdpPacket>,
) -> Result<()> {
    info!("UDP transmit handler started...");

    // Process incoming UDP packets
    while let Some(udp_packet) = udp_receive_rx.recv().await {
        udp_writer.send_to(
            &udp_packet.payload,
            &udp_packet.src_addr,
            &udp_packet.dst_addr,
        )?;
    }
    warn!("UDP transmit handler closed");
    Ok(())
}
