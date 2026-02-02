use crate::crypto::CryptoManager;
use crate::storage::model::Record;
use anyhow::Result;
use std::sync::Arc;
use tokio::sync::oneshot;

/// A task for a PQC worker to encrypt a record
pub struct PqcTask {
    /// The record to be encrypted
    pub record: Record,
    /// KEM public key for encryption
    pub kem_pk: Vec<u8>,
    /// Optional DSA keypair for signing
    pub dsa_keypair: Option<crate::crypto::signature::Keypair>,
    /// Channel for returning the encrypted record
    pub response: oneshot::Sender<Result<(Record, Vec<u8>)>>,
}

/// A pool of workers for performing CPU-intensive PQC encryption tasks
pub struct PqcWorkerPool {
    sender: tokio::sync::mpsc::Sender<PqcTask>,
}

impl PqcWorkerPool {
    /// Initializes a new worker pool
    #[must_use]
    pub fn new(_worker_count: usize) -> Self {
        let (tx, mut rx) = tokio::sync::mpsc::channel::<PqcTask>(1024);
        let crypto = Arc::new(CryptoManager::new());

        // Correct implementation: One loop that spawns blocking tasks
        let crypto_inner = crypto;
        tokio::spawn(async move {
            while let Some(task) = rx.recv().await {
                let crypto_ref = crypto_inner.clone();
                tokio::task::spawn_blocking(move || {
                    let result = Self::process_task(
                        &crypto_ref,
                        task.record,
                        &task.kem_pk,
                        task.dsa_keypair.as_ref(),
                    );
                    let _ = task.response.send(result);
                });
            }
        });

        Self { sender: tx }
    }

    fn process_task(
        crypto: &Arc<CryptoManager>,
        record: Record,
        kem_pk: &[u8],
        dsa_keypair: Option<&crate::crypto::signature::Keypair>,
    ) -> Result<(Record, Vec<u8>)> {
        let serialized = bincode::serialize(&record)?;
        let encrypted = crypto.encrypt_at_rest(&serialized, kem_pk, dsa_keypair)?;
        let bin = bincode::serialize(&encrypted)?;
        Ok((record, bin))
    }

    /// Submits a record for encryption to the worker pool
    ///
    /// # Errors
    ///
    /// Returns an error if the worker pool channel is closed.
    pub async fn submit(
        &self,
        record: Record,
        kem_pk: Vec<u8>,
        dsa_keypair: Option<crate::crypto::signature::Keypair>,
    ) -> Result<oneshot::Receiver<Result<(Record, Vec<u8>)>>> {
        let (tx, rx) = oneshot::channel();
        let task = PqcTask {
            record,
            kem_pk,
            dsa_keypair,
            response: tx,
        };
        Box::pin(self.sender.send(task))
            .await
            .map_err(|_| anyhow::anyhow!("Worker pool channel closed"))?;
        Ok(rx)
    }
}
