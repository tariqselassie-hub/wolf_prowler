use sentinel::start_sentinel;

#[tokio::main]
async fn main() -> std::io::Result<()> {
    start_sentinel().await
}
