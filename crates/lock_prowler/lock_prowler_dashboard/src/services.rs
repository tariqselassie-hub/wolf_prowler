use crate::models::SystemStats;

use dioxus_fullstack::prelude::*;
use lock_prowler::headless::HeadlessStatus;

#[cfg(feature = "server")]
use lock_prowler::headless::HeadlessWolfProwler;
#[cfg(feature = "server")]
use once_cell::sync::Lazy;
#[cfg(feature = "server")]
use tokio::sync::Mutex as AsyncMutex;

// Global state simulation
#[cfg(feature = "server")]
pub static PROWLER: Lazy<AsyncMutex<Option<HeadlessWolfProwler>>> =
    Lazy::new(|| AsyncMutex::new(None));

#[server]
pub async fn get_fullstack_stats() -> Result<SystemStats, ServerFnError> {
    Ok(SystemStats {
        volume_size: "512_GB_BitLocker".to_string(),
        encrypted_sectors: 98.2,
        entropy: 0.88,
        db_status: "CONNECTED".to_string(),
    })
}

#[server]
pub async fn run_prowler_scan() -> Result<String, ServerFnError> {
    // Integration point for HeadlessWolfProwler
    // Example: lock_prowler::engine::HeadlessWolfProwler::run().await?;

    // Simulating backend processing time
    tokio::time::sleep(std::time::Duration::from_secs(2)).await;

    Ok(
        "Scan completed: 1,024 sectors verified. No unauthorized modifications detected."
            .to_string(),
    )
}

#[server]
pub async fn stream_prowler_logs() -> Result<Vec<String>, ServerFnError> {
    // Streaming disabled temporarily due to serialization issues
    #[cfg(feature = "server")]
    {
        // let prowler_lock = PROWLER.lock().await;
        // let prowler = prowler_lock
        //     .as_ref()
        //     .ok_or_else(|| ServerFnError::new("Prowler not initialized"))?;
        // let rx = prowler.subscribe_logs();

        // // Convert broadcast receiver to a stream
        // let stream = tokio_stream::wrappers::BroadcastStream::new(rx).map(|res| match res {
        //     Ok(msg) => Ok(msg),
        //     Err(e) => Err(ServerFnError::new(e.to_string())),
        // });

        // Ok(Box::pin(stream))
        Ok(Vec::new())
    }
    #[cfg(not(feature = "server"))]
    Ok(Vec::new())
}

#[server]
pub async fn stream_prowler_status() -> Result<Vec<HeadlessStatus>, ServerFnError> {
    // Streaming disabled temporarily due to serialization issues
    #[cfg(feature = "server")]
    {
        // let prowler_lock = PROWLER.lock().await;
        // let prowler = prowler_lock
        //     .as_ref()
        //     .ok_or_else(|| ServerFnError::new("Prowler not initialized"))?;
        // let rx = prowler.subscribe_status();

        // // Convert broadcast receiver to a stream
        // let stream = tokio_stream::wrappers::BroadcastStream::new(rx).map(|res| match res {
        //     Ok(s) => Ok(s),
        //     Err(e) => Err(ServerFnError::new(e.to_string())),
        // });

        // Ok(Box::pin(stream))
        Ok(Vec::new())
    }
    #[cfg(not(feature = "server"))]
    Ok(Vec::new())
}
