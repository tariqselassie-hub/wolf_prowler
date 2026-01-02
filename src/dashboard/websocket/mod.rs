// FILE: src/dashboard/websocket/mod.rs
// WebSocket server implementation for real-time updates

use axum::{
    extract::ws::{Message, WebSocket, WebSocketUpgrade},
    response::IntoResponse,
};
use futures_util::StreamExt;
use std::{
    collections::HashMap,
    sync::{Arc, RwLock},
};
use tokio::sync::broadcast;
use uuid::Uuid;
use futures_util::SinkExt;

/// Represents a connected WebSocket client
pub struct Client {
    pub id: Uuid,
    pub sender: tokio::sync::mpsc::UnboundedSender<Message>,
}

/// Manages WebSocket connections and broadcasts
#[derive(Clone)]
pub struct WebSocketManager {
    clients: Arc<RwLock<HashMap<Uuid, Client>>>,
    tx: broadcast::Sender<Message>,
}

impl WebSocketManager {
    pub fn new() -> Self {
        let (tx, _) = broadcast::channel(100);
        Self {
            clients: Arc::new(RwLock::new(HashMap::new())),
            tx,
        }
    }

    /// Handle new WebSocket connection
    pub async fn handle_connection(
        &self,
        ws: WebSocketUpgrade,
    ) -> impl IntoResponse {
        let this = self.clone();
        ws.on_upgrade(move |socket| async move { this.handle_socket(socket).await })
    }

    /// Process messages from a WebSocket connection
    async fn handle_socket(&self, socket: WebSocket) {
        let (mut sender, mut receiver) = socket.split();
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
        let id = Uuid::new_v4();
        let mut rx_broadcast = self.tx.subscribe();

        // Add client to active connections
        {
            let mut clients = self.clients.write().unwrap();
            clients.insert(
                id,
                Client {
                    id,
                    sender: tx.clone(),
                },
            );
        }

        // Spawn a task to read messages from the client
        let read_task = tokio::spawn({
            let clients = self.clients.clone();
            let tx_broadcast = self.tx.clone();

            async move {
                while let Some(Ok(msg)) = receiver.next().await {
                    if let Message::Text(text) = msg {
                        // Broadcast message to all clients
                        if let Err(e) = tx_broadcast.send(Message::Text(text)) {
                            eprintln!("Error broadcasting message: {}", e);
                        }
                    }
                }

                // Remove client on disconnect
                clients.write().unwrap().remove(&id);
            }
        });

        // Spawn a task to send messages to the client
        let write_task = tokio::spawn(async move {
            while let Some(msg) = rx.recv().await {
                if sender.send(msg).await.is_err() {
                    break;
                }
            }
        });

        // Spawn a task to handle broadcast messages
        let broadcast_task = tokio::spawn(async move {
            while let Ok(msg) = rx_broadcast.recv().await {
                if tx.send(msg).is_err() {
                    break;
                }
            }
        });

        // Wait for any of the tasks to complete
        tokio::select! {
            _ = read_task => (),
            _ = write_task => (),
            _ = broadcast_task => (),
        }
    }

    /// Broadcast a message to all connected clients
    pub fn broadcast(&self, msg: Message) {
        let _ = self.tx.send(msg);
    }
}

// Implement Default for WebSocketManager
impl Default for WebSocketManager {
    fn default() -> Self {
        Self::new()
    }
}