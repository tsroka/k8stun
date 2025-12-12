//! Bidirectional stream copying for tunneling data.
//!
//! This module handles the data plane - copying bytes between
//! the userspace TCP stack and Kubernetes port-forward streams.

use crate::vip::ActiveConnection;
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_util::io::{InspectReader, InspectWriter};

/// Pipes data bidirectionally between two streams.
///
/// This function copies data in both directions concurrently:
/// - From `client` to `server`
/// - From `server` to `client`
///
/// The pipe continues until either side closes or an error occurs.
pub async fn pipe<C, S>(
    conn: ActiveConnection,
    client: C,
    mut server: S,
) -> std::io::Result<(u64, u64)>
where
    C: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let conn_read = Arc::new(conn);
    let conn_write = conn_read.clone();

    let client = InspectReader::new(client, move |data| {
        conn_read.add_bytes_sent(data.len() as u64);
    });

    let mut client = InspectWriter::new(client, move |data| {
        conn_write.add_bytes_received(data.len() as u64);
    });

    tokio::io::copy_bidirectional(&mut client, &mut server).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vip::ConnectionId;
    use std::net::Ipv4Addr;
    use std::sync::atomic::Ordering;
    use tokio::io::{duplex, AsyncReadExt, AsyncWriteExt};
    use tokio::sync::mpsc;

    #[tokio::test]
    async fn test_pipe_basic() {
        let (client, mut server_end) = duplex(1024);
        let (server, mut client_end) = duplex(1024);

        // Spawn a task to simulate the "client" side sending data
        let client_task = tokio::spawn(async move {
            client_end.write_all(b"hello").await.unwrap();
            client_end.shutdown().await.unwrap();
            // Keep the connection alive to read the response
            let mut response = Vec::new();
            client_end.read_to_end(&mut response).await.unwrap();
            response
        });

        // Spawn a task to echo data on the "server" side (minus 1 byte)
        let server_task = tokio::spawn(async move {
            let mut buf = [0u8; 1024];
            if let Ok(n) = server_end.read(&mut buf).await {
                if n > 0 {
                    // Echo back n-1 bytes
                    server_end.write_all(&buf[..(n - 1)]).await.unwrap();
                }
            }
            server_end.shutdown().await.unwrap();
        });

        let (tx, _rx) = mpsc::channel(10);
        let conn = ActiveConnection::new(Ipv4Addr::new(1, 1, 1, 1), ConnectionId::new(1), tx);
        let stats = conn.stats();
        let result = pipe(conn, client, server).await;

        let (bytes_from_client, bytes_from_server) = result.expect("pipe to succeed");
        // copy_bidirectional returns (bytes read from first, bytes read from second)
        // - bytes_from_client = 4 (the "hell" echo written by server_end)
        // - bytes_from_server = 5 (the "hello" written by client_end)
        assert_eq!(bytes_from_client, 4);
        assert_eq!(bytes_from_server, 5);
        assert_eq!(stats.bytes_sent.load(Ordering::Relaxed), bytes_from_client);
        assert_eq!(
            stats.bytes_received.load(Ordering::Relaxed),
            bytes_from_server
        );

        // Wait for both tasks to complete
        server_task.await.unwrap();
        let response = client_task.await.unwrap();
        assert_eq!(response, b"hell"); // "hello" minus 1 byte
    }
}
