// crates/node/src/finalized_tx.rs
// A bounded async channel that the validator_pipeline writes verified
// Transaction objects into, and the block_producer drains on each tick.
// Using a tokio broadcast channel allows multiple consumers (e.g. a
// websocket event stream) to observe finalised transactions.

use common::Transaction;
use std::sync::Arc;
use tokio::sync::{mpsc, Mutex};

/// Capacity of the finalized-tx channel.
/// At 5-second block intervals with ~100 tx/block this is comfortable.
const CHANNEL_CAPACITY: usize = 512;

/// Sender half — held by the validator_pipeline.
pub type FinalizedTxSender = mpsc::Sender<Transaction>;

/// Receiver half — held (behind a Mutex) by the block_producer so it
/// can drain without needing to clone the receiver.
pub type FinalizedTxReceiver = Arc<Mutex<mpsc::Receiver<Transaction>>>;

/// Create a matched sender/receiver pair.
pub fn channel() -> (FinalizedTxSender, FinalizedTxReceiver) {
    let (tx, rx) = mpsc::channel(CHANNEL_CAPACITY);
    (tx, Arc::new(Mutex::new(rx)))
}

/// Drain all currently queued transactions without blocking.
/// Returns an empty Vec if nothing is ready.
pub async fn drain(rx: &FinalizedTxReceiver) -> Vec<Transaction> {
    let mut guard = rx.lock().await;
    let mut txs = Vec::new();
    loop {
        match guard.try_recv() {
            Ok(tx) => txs.push(tx),
            Err(mpsc::error::TryRecvError::Empty) => break,
            Err(mpsc::error::TryRecvError::Disconnected) => break,
        }
    }
    txs
}
