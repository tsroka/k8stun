//! Userspace TCP/IP stack implementation using lwIP.

use anyhow::Result;
use async_trait::async_trait;
use futures::{Sink, Stream};
use lwip::NetStack;
use std::net::SocketAddr;
use std::pin::Pin;
use std::task::{Context, Poll};
use tun2::AsyncDevice;

use super::common::{self, StackBackend, StackComponents, UdpSender};

/// Type alias for TcpStream using the lwIP backend.
#[allow(dead_code)]
pub type TcpStream = common::TcpStream<lwip::TcpStream>;

/// Type alias for AcceptedConnection using the lwIP backend.
pub type AcceptedConnection = common::AcceptedConnection<lwip::TcpStream>;

/// Type alias for NetworkStack using the lwIP backend.
pub type NetworkStack = common::NetworkStack<lwip::TcpStream>;

/// The lwIP backend implementation.
pub struct LwipBackend;

// Wrapper for lwip's UDP writer to implement UdpSender trait
pub struct LwipUdpWriter(lwip::UdpSendHalf);

#[async_trait]
impl UdpSender for LwipUdpWriter {
    async fn send_udp(
        &mut self,
        payload: Vec<u8>,
        src: SocketAddr,
        dst: SocketAddr,
    ) -> Result<(), std::io::Error> {
        self.0
            .send_to(&payload, &src, &dst)
            .map_err(|e| std::io::Error::other(e.to_string()))
    }
}

// Wrapper types for lwip's sink/stream to satisfy trait bounds
pub struct LwipPacketSink(futures::stream::SplitSink<NetStack, Vec<u8>>);
pub struct LwipPacketStream(futures::stream::SplitStream<NetStack>);

impl Sink<Vec<u8>> for LwipPacketSink {
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

impl Stream for LwipPacketStream {
    type Item = Result<Vec<u8>, std::io::Error>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        Pin::new(&mut self.0).poll_next(cx)
    }
}

#[async_trait]
impl StackBackend for LwipBackend {
    type InnerTcpStream = lwip::TcpStream;
    type PacketSink = LwipPacketSink;
    type PacketStream = LwipPacketStream;
    type PacketError = std::io::Error;
    type TcpListener = lwip::TcpListener;
    type UdpReader = lwip::UdpRecvHalf;
    type UdpWriter = LwipUdpWriter;

    fn build() -> Result<StackComponents<Self>> {
        use futures::StreamExt;

        let (stack, tcp_listener, udp_socket) =
            NetStack::new().map_err(|e| anyhow::anyhow!("Failed to build network stack: {}", e))?;

        let (sink, stream) = stack.split();
        let (udp_writer, udp_reader) = udp_socket.split();

        Ok(StackComponents {
            packet_sink: LwipPacketSink(sink),
            packet_stream: LwipPacketStream(stream),
            tcp_listener: Some(tcp_listener),
            udp_reader: Some(udp_reader),
            udp_writer: Some(LwipUdpWriter(udp_writer)),
        })
    }

    fn name() -> &'static str {
        "lwIP"
    }
}

impl NetworkStack {
    /// Creates a new network stack using the given TUN device (lwIP backend).
    pub async fn new(device: AsyncDevice) -> Result<Self> {
        Self::create::<LwipBackend>(device).await
    }
}
