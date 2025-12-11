//! HTTP route handlers for the VIP API.

use axum::{
    extract::State,
    response::{
        sse::{Event, KeepAlive, Sse},
        Json,
    },
};
use std::convert::Infallible;
use tokio_stream::{wrappers::BroadcastStream, Stream, StreamExt};

use crate::vip::VipManager;

use super::types::{VipEvent, VipInfo, VipSnapshot};

/// GET /vips - Returns current VIP mappings as JSON.
pub async fn get_vips(State(vip_manager): State<VipManager>) -> Json<VipSnapshot> {
    let mappings = vip_manager.get_all_target_mappings().await;

    let vips = mappings.into_iter().map(VipInfo::from).collect();

    Json(VipSnapshot { vips })
}

/// GET /events - SSE endpoint for real-time VIP updates.
///
/// First message is a snapshot of all current VIPs, then delta updates follow.
pub async fn events(
    State(vip_manager): State<VipManager>,
) -> Sse<impl Stream<Item = Result<Event, Infallible>>> {
    // Get initial snapshot
    let mappings = vip_manager.get_all_target_mappings().await;
    let initial_vips: Vec<VipInfo> = mappings.into_iter().map(VipInfo::from).collect();

    let snapshot_event = VipEvent::Snapshot { vips: initial_vips };

    // Subscribe to updates
    let rx = vip_manager.subscribe();
    let update_stream = BroadcastStream::new(rx).filter_map(|result| {
        result.ok().map(|update| {
            let event = VipEvent::from_update(update);
            let data = serde_json::to_string(&event).unwrap_or_default();
            Ok(Event::default().data(data))
        })
    });

    // Create initial snapshot event
    let snapshot_data = serde_json::to_string(&snapshot_event).unwrap_or_default();
    let initial_event =
        futures::stream::once(
            async move { Ok::<_, Infallible>(Event::default().data(snapshot_data)) },
        );

    // Combine initial snapshot with update stream
    let combined_stream = initial_event.chain(update_stream);

    Sse::new(combined_stream).keep_alive(KeepAlive::default())
}
