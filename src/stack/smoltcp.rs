//! Userspace TCP/IP stack implementation using smoltcp via netstack-smoltcp.

use anyhow::Result;
use async_trait::async_trait;
use futures::{Sink, SinkExt, Stream};
use netstack_smoltcp::StackBuilder;
use std::net::SocketAddr;
use std::pin::Pin;
use std::task::{Context, Poll};
use tun2::AsyncDevice;

use super::common::{self, StackBackend, StackComponents, UdpSender};

/// Type alias for TcpStream using the smoltcp backend.
#[allow(dead_code)]
pub type TcpStream = common::TcpStream<netstack_smoltcp::TcpStream>;

/// Type alias for AcceptedConnection using the smoltcp backend.
pub type AcceptedConnection = common::AcceptedConnection<netstack_smoltcp::TcpStream>;

/// Type alias for NetworkStack using the smoltcp backend.
pub type NetworkStack = common::NetworkStack<netstack_smoltcp::TcpStream>;

/// The smoltcp backend implementation.
pub struct SmoltcpBackend;

// Wrapper for smoltcp's UDP writer to implement UdpSender trait
pub struct SmoltcpUdpWriter(netstack_smoltcp::udp::WriteHalf);

#[async_trait]
impl UdpSender for SmoltcpUdpWriter {
    async fn send_udp(
        &mut self,
        payload: Vec<u8>,
        src: SocketAddr,
        dst: SocketAddr,
    ) -> Result<(), std::io::Error> {
        self.0.send((payload, src, dst)).await
    }
}

// Wrapper types for smoltcp's sink/stream to satisfy trait bounds
pub struct SmoltcpPacketSink(futures::stream::SplitSink<netstack_smoltcp::Stack, Vec<u8>>);
pub struct SmoltcpPacketStream(futures::stream::SplitStream<netstack_smoltcp::Stack>);

impl Sink<Vec<u8>> for SmoltcpPacketSink {
    type Error = std::io::Error;

    fn poll_ready(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Pin::new(&mut self.0).poll_ready(cx)
    }

    fn start_send(mut self: Pin<&mut Self>, item: Vec<u8>) -> Result<(), Self::Error> {
        Pin::new(&mut self.0).start_send(item)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Pin::new(&mut self.0).poll_flush(cx)
    }

    fn poll_close(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Pin::new(&mut self.0).poll_close(cx)
    }
}

impl Stream for SmoltcpPacketStream {
    type Item = Result<Vec<u8>, std::io::Error>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        Pin::new(&mut self.0).poll_next(cx)
    }
}

#[async_trait]
impl StackBackend for SmoltcpBackend {
    type InnerTcpStream = netstack_smoltcp::TcpStream;
    type PacketSink = SmoltcpPacketSink;
    type PacketStream = SmoltcpPacketStream;
    type PacketError = std::io::Error;
    type TcpListener = netstack_smoltcp::tcp::TcpListener;
    type UdpReader = netstack_smoltcp::udp::ReadHalf;
    type UdpWriter = SmoltcpUdpWriter;

    fn build() -> Result<StackComponents<Self>> {
        use futures::StreamExt;

        let (stack, runner, udp_socket, tcp_listener) = StackBuilder::default()
            .stack_buffer_size(512)
            .tcp_buffer_size(65535)
            .enable_udp(true)
            .enable_tcp(true)
            .enable_icmp(true)
            .build()
            .map_err(|e| anyhow::anyhow!("Failed to build network stack: {}", e))?;

        // Spawn the runner task if present (required for smoltcp)
        if let Some(runner) = runner {
            tokio::spawn(runner);
        }

        let (sink, stream) = stack.split();

        let (udp_reader, udp_writer) = match udp_socket {
            Some(socket) => {
                let (r, w) = socket.split();
                (Some(r), Some(SmoltcpUdpWriter(w)))
            }
            None => (None, None),
        };

        Ok(StackComponents {
            packet_sink: SmoltcpPacketSink(sink),
            packet_stream: SmoltcpPacketStream(stream),
            tcp_listener,
            udp_reader,
            udp_writer,
        })
    }

    fn name() -> &'static str {
        "smoltcp"
    }
}

impl NetworkStack {
    /// Creates a new network stack using the given TUN device (smoltcp backend).
    pub async fn new(device: AsyncDevice) -> Result<Self> {
        Self::create::<SmoltcpBackend>(device).await
    }
}
