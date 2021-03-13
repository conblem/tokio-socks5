use std::error::Error;
use tracing::{info_span, Instrument};

mod socks5;
use socks5::Socks5Listener;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error + Send + Sync>> {
    tracing_subscriber::fmt::init();

    async {
        let mut socks5 = Socks5Listener::new()?;
        socks5.listen().await
    }
    .instrument(info_span!("main"))
    .await
}
