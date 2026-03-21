//! CloakCat agent entry point.

mod beacon;
mod bof;
mod config;
mod exec;
mod host;
mod tasks;
mod transport;
mod tunnel;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    beacon::run().await
}
