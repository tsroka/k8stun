//! HTTP API for exposing VIP manager state.
//!
//! This module provides a REST API and Server-Sent Events (SSE) endpoint
//! for querying and monitoring VIP allocations in real-time.

mod handlers;
mod types;

use axum::{routing::get, Router};
use std::net::SocketAddr;
use tokio::net::TcpListener;
use tracing::info;

use crate::vip::VipManager;

/// Starts the HTTP API server.
///
/// # Arguments
/// * `port` - The port to listen on
/// * `vip_manager` - The VIP manager handle to query
///
/// # Returns
/// A future that runs the server until shutdown.
pub async fn start_server(port: u16, vip_manager: VipManager) -> anyhow::Result<()> {
    let app = Router::new()
        .route("/vips", get(handlers::get_vips))
        .route("/events", get(handlers::events))
        .with_state(vip_manager);

    let addr = SocketAddr::from(([0, 0, 0, 0], port));
    let listener = TcpListener::bind(addr).await?;

    info!("API server listening on http://{}", addr);

    axum::serve(listener, app).await?;

    Ok(())
}

