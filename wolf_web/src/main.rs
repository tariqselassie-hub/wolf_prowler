use wolf_web::run_web_server;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    run_web_server().await
}
