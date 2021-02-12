mod config;
mod gemini;
mod hydepark;
mod server;
mod storage;

use async_std::task::block_on;
use config::Config;
use hydepark::Hydepark;
use server::Server;

type BoxedError = Box<dyn std::error::Error + Send + Sync>;
type Result<T> = std::result::Result<T, BoxedError>;

async fn start(config: Config) -> Result<()> {
    let storage = storage::create(&config).await?;
    let hydepark = Hydepark::new(config.clone(), storage);
    let mut server = Server::new(config, hydepark).await?;
    server.serve().await
}

fn main() -> Result<()> {
    env_logger::init();
    block_on(start(Config::read()))
}
