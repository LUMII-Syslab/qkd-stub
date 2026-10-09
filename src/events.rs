//! Request activity events for observers such as the GUI.
//!
//! Events carry no query strings, request bodies, key IDs, or key material.
use time::OffsetDateTime;
use tokio::sync::broadcast;

pub type EventSender = broadcast::Sender<Event>;
pub type EventReceiver = broadcast::Receiver<Event>;
pub use broadcast::error::RecvError;

#[derive(Clone, Debug)]
pub struct Event {
    pub time: OffsetDateTime,
    /// Configured SAE ID of the authenticated caller, if any.
    pub caller_sae: Option<String>,
    pub method: String,
    /// Matched route template, or `(unmatched)`.
    pub route: String,
    pub status: u16,
    pub duration_ms: u64,
}

pub fn channel() -> (EventSender, EventReceiver) {
    broadcast::channel(1024)
}
