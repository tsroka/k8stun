//! Common types and traits shared between network stack implementations.

use std::fmt::Display;
use std::net::SocketAddr;
use std::pin::Pin;
use std::task::{Context, Poll};

use anyhow::Result;
use async_trait::async_trait;
use futures::{Sink, SinkExt, Stream, StreamExt};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::sync::mpsc;
use tracing::{debug, error, info, trace, warn};
use tun2::AsyncDevice;

// ============================================================================
// Core Types
// ============================================================================

/// A TCP stream wrapper that works with any async read/write inner type.
///
/// This generic wrapper provides a consistent interface regardless of
/// the underlying network stack implementation (lwIP or smoltcp).
pub struct TcpStream<T> {
    inner: T,
    pub local_addr: SocketAddr,
    pub peer_addr: SocketAddr,
}

impl<T> TcpStream<T> {
    /// Creates a new TcpStream wrapping the given inner stream.
    pub fn new(inner: T, local_addr: SocketAddr, peer_addr: SocketAddr) -> Self {
        Self {
            inner,
            local_addr,
            peer_addr,
        }
    }

    /// Returns a mutable reference to the inner stream.
    #[allow(dead_code)]
    pub fn inner_mut(&mut self) -> &mut T {
        &mut self.inner
    }

    /// Consumes the TcpStream and returns the inner stream.
    #[allow(dead_code)]
    pub fn into_inner(self) -> T {
        self.inner
    }
}

impl<T: AsyncRead + AsyncWrite + Unpin> TcpStream<T> {
    /// Splits the stream into read and write halves.
    #[allow(dead_code)]
    pub fn into_split(self) -> (impl AsyncRead, impl AsyncWrite) {
        tokio::io::split(self.inner)
    }
}

impl<T: AsyncRead + Unpin> AsyncRead for TcpStream<T> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl<T: AsyncWrite + Unpin> AsyncWrite for TcpStream<T> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

/// A UDP packet with source and destination addresses.
pub struct UdpPacket {
    pub src_addr: SocketAddr,
    pub dst_addr: SocketAddr,
    pub payload: Vec<u8>,
}

/// Information about an accepted TCP connection.
pub struct AcceptedConnection<T> {
    pub stream: TcpStream<T>,
    /// The destination IP address.
    pub dst_ip: std::net::Ipv4Addr,
    /// The destination port from the intercepted connection.
    pub dst_port: u16,
}

/// The userspace network stack that handles TCP connections.
pub struct NetworkStack<T> {
    /// Channel to receive accepted TCP connections.
    pub tcp_rx: mpsc::Receiver<AcceptedConnection<T>>,
    /// Channel to receive accepted UDP packets.
    pub udp_received_rx: mpsc::Receiver<UdpPacket>,
    /// Channel to send UDP packets.
    pub udp_send_tx: mpsc::Sender<UdpPacket>,
}

impl<T> NetworkStack<T> {
    /// Splits the network stack into its component channels.
    pub fn split(
        self,
    ) -> (
        mpsc::Receiver<AcceptedConnection<T>>,
        mpsc::Sender<UdpPacket>,
        mpsc::Receiver<UdpPacket>,
    ) {
        (self.tcp_rx, self.udp_send_tx, self.udp_received_rx)
    }
}

// ============================================================================
// Backend Traits
// ============================================================================

/// Trait for UDP packet senders.
///
/// This abstracts over different UDP writer implementations:
/// - lwip uses a synchronous `send_to` method
/// - smoltcp uses an async `Sink`
#[async_trait]
pub trait UdpSender: Send {
    /// Send a UDP packet.
    async fn send_udp(
        &mut self,
        payload: Vec<u8>,
        src: SocketAddr,
        dst: SocketAddr,
    ) -> Result<(), std::io::Error>;
}

/// Trait for network stack backends.
///
/// This trait abstracts over different network stack implementations (lwIP, smoltcp)
/// and provides a unified interface for creating and running the stack.
#[async_trait]
pub trait StackBackend: Sized + Send + 'static {
    /// The inner TCP stream type from this backend.
    type InnerTcpStream: AsyncRead + AsyncWrite + Unpin + Send + 'static;

    /// The packet sink type for sending packets to the stack.
    type PacketSink: Sink<Vec<u8>> + Unpin + Send + 'static;

    /// The packet stream type for receiving packets from the stack.
    type PacketStream: Stream<Item = Result<Vec<u8>, Self::PacketError>> + Unpin + Send + 'static;

    /// The error type for packet stream operations.
    type PacketError: Display + Send;

    /// The TCP listener type.
    type TcpListener: Stream<Item = (Self::InnerTcpStream, SocketAddr, SocketAddr)>
        + Unpin
        + Send
        + 'static;

    /// The UDP reader type.
    type UdpReader: Stream<Item = (Vec<u8>, SocketAddr, SocketAddr)> + Unpin + Send + 'static;

    /// The UDP writer type.
    type UdpWriter: UdpSender + 'static;

    /// Build the network stack components.
    ///
    /// Returns all the components needed to run the stack:
    /// - packet_sink/stream: for TUN <-> stack bridging
    /// - tcp_listener: for accepting TCP connections
    /// - udp_reader/writer: for UDP packet handling
    fn build() -> Result<StackComponents<Self>>;

    /// Get the backend name for logging.
    fn name() -> &'static str;
}

/// Components returned by `StackBackend::build()`.
pub struct StackComponents<B: StackBackend> {
    pub packet_sink: B::PacketSink,
    pub packet_stream: B::PacketStream,
    pub tcp_listener: Option<B::TcpListener>,
    pub udp_reader: Option<B::UdpReader>,
    pub udp_writer: Option<B::UdpWriter>,
}

// ============================================================================
// Generic Helper Functions
// ============================================================================

impl<T: AsyncRead + AsyncWrite + Unpin + Send + 'static> NetworkStack<T> {
    /// Creates a new network stack using the given TUN device and backend.
    pub async fn create<B>(device: AsyncDevice) -> Result<Self>
    where
        B: StackBackend<InnerTcpStream = T>,
    {
        let (udp_received_tx, udp_received_rx) = mpsc::channel(64);
        let (udp_send_tx, udp_send_rx) = mpsc::channel(64);
        let (tcp_tx, tcp_rx) = mpsc::channel(64);

        let components = B::build()?;

        // Spawn the packet processing task (TUN <-> Stack)
        tokio::spawn(run_tun_stack_bridge(
            device,
            components.packet_sink,
            components.packet_stream,
        ));

        // Spawn the TCP connection handling task
        if let Some(tcp_listener) = components.tcp_listener {
            tokio::spawn(async move {
                if let Err(e) = run_tcp_listener(tcp_listener, tcp_tx).await {
                    error!("TCP listener error: {}", e);
                }
            });
        }

        // Spawn the UDP handling tasks
        if let Some(udp_reader) = components.udp_reader {
            tokio::spawn(async move {
                if let Err(e) = run_udp_rx_handler(udp_reader, udp_received_tx).await {
                    error!("UDP handler error: {}", e);
                }
            });
        }

        if let Some(udp_writer) = components.udp_writer {
            tokio::spawn(async move {
                if let Err(e) = run_udp_tx_handler(udp_writer, udp_send_rx).await {
                    error!("UDP handler error: {}", e);
                }
            });
        }

        info!(
            "Network stack started ({} backend), waiting for connections...",
            B::name()
        );

        Ok(Self {
            tcp_rx,
            udp_received_rx,
            udp_send_tx,
        })
    }
}

/// Bridge between TUN device and the network stack.
/// Reads packets from TUN and sends to Stack, reads from Stack and sends to TUN.
async fn run_tun_stack_bridge<Si, St, E>(
    device: AsyncDevice,
    mut stack_sink: Si,
    mut stack_stream: St,
) where
    Si: Sink<Vec<u8>> + Unpin + Send,
    St: Stream<Item = Result<Vec<u8>, E>> + Unpin + Send,
    E: Display,
{
    let (mut tun_reader, mut tun_writer) = tokio::io::split(device);

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
                    if let Err(_e) = stack_sink.send(packet).await {
                        error!("Failed to send packet to stack");
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
async fn run_tcp_listener<T, L>(
    mut tcp_listener: L,
    connection_tx: mpsc::Sender<AcceptedConnection<T>>,
) -> Result<()>
where
    T: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    L: Stream<Item = (T, SocketAddr, SocketAddr)> + Unpin,
{
    while let Some((tcp_stream, local_addr, peer_addr)) = tcp_listener.next().await {
        debug!("TCP connection: {} -> {}", local_addr, peer_addr);

        // Look up the target for this VIP
        let dst_ip = match peer_addr {
            SocketAddr::V4(addr) => *addr.ip(),
            SocketAddr::V6(_) => {
                warn!("IPv6 not supported, refusing connection");
                drop(tcp_stream);
                continue;
            }
        };

        let dst_port = peer_addr.port();
        let stream = TcpStream::new(tcp_stream, local_addr, peer_addr);

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

/// Handles incoming UDP packets.
async fn run_udp_rx_handler<R>(
    mut udp_reader: R,
    client_udp_receive_tx: mpsc::Sender<UdpPacket>,
) -> Result<()>
where
    R: Stream<Item = (Vec<u8>, SocketAddr, SocketAddr)> + Unpin,
{
    info!("UDP receive handler started...");

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

/// Handles outgoing UDP packets.
async fn run_udp_tx_handler<W>(
    mut udp_writer: W,
    mut udp_receive_rx: mpsc::Receiver<UdpPacket>,
) -> Result<()>
where
    W: UdpSender,
{
    info!("UDP transmit handler started...");

    while let Some(udp_packet) = udp_receive_rx.recv().await {
        if let Err(e) = udp_writer
            .send_udp(udp_packet.payload, udp_packet.src_addr, udp_packet.dst_addr)
            .await
        {
            error!("Failed to send UDP packet: {}", e);
            break;
        }
    }
    warn!("UDP transmit handler closed");
    Ok(())
}
