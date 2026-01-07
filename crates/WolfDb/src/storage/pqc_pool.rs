use crate::crypto::CryptoManager;
use crate::storage::model::Record;
use anyhow::Result;
use std::sync::Arc;
use tokio::sync::oneshot;

pub struct PqcTask {
    pub record: Record,
    pub kem_pk: Vec<u8>,
    pub dsa_keypair: Option<crate::crypto::signature::Keypair>,
    pub response: oneshot::Sender<Result<(Record, Vec<u8>)>>,
}

pub struct PqcWorkerPool {
    sender: tokio::sync::mpsc::Sender<PqcTask>,
}

impl PqcWorkerPool {
    pub fn new(_worker_count: usize) -> Self {
        let (tx, mut rx) = tokio::sync::mpsc::channel::<PqcTask>(1024);
        let crypto = Arc::new(CryptoManager::new());

        // Correct implementation: One loop that spawns blocking tasks
        let crypto_inner = crypto.clone();
        tokio::spawn(async move {
            while let Some(task) = rx.recv().await {
                let crypto_ref = crypto_inner.clone();
                tokio::task::spawn_blocking(move || {
                    let result = Self::process_task(
                        crypto_ref,
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
        crypto: Arc<CryptoManager>,
        record: Record,
        kem_pk: &[u8],
        dsa_keypair: Option<&crate::crypto::signature::Keypair>,
    ) -> Result<(Record, Vec<u8>)> {
        let serialized = bincode::serialize(&record)?;
        let encrypted = crypto.encrypt_at_rest(&serialized, kem_pk, dsa_keypair)?;
        let bin = bincode::serialize(&encrypted)?;
        Ok((record, bin))
    }

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
        self.sender
            .send(task)
            .await
            .map_err(|_| anyhow::anyhow!("Worker pool channel closed"))?;
        Ok(rx)
    }
}
