use axum::{Router, handler::HandlerWithoutStateExt, http::StatusCode, response::IntoResponse};
use std::net::SocketAddr;
use tokio::net::TcpListener;
use tower_http::{services::ServeDir, trace::TraceLayer};
use tracing::info;

/// Fallback handler for routes that are not found.
async fn fallback_handler() -> impl IntoResponse {
    (StatusCode::NOT_FOUND, "404: Not Found")
}

/// The main entry point for running the Wolf Web dashboard.
///
/// This function sets up the Axum router, binds to a TCP socket,
/// and starts serving HTTP requests.
pub async fn run_web_server() -> anyhow::Result<()> {
    let app = Router::new()
        // Serve static files from the `static` directory
        .nest_service(
            "/",
            ServeDir::new("wolf_web/static").fallback(fallback_handler.into_service()),
        )
        // Apply a tracing layer to log requests and responses.
        .layer(TraceLayer::new_for_http());

    let addr = SocketAddr::from(([127, 0, 0, 1], 3000));
    let listener = TcpListener::bind(addr).await?;
    info!("Wolf Web dashboard listening on http://{}", addr);

    axum::serve(listener, app).await?;
    Ok(())
}
