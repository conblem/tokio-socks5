use std::error::Error;

mod socks5;
use socks5::Socks5Listener;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error + Send + Sync>> {
    let mut socks5 = Socks5Listener::new().await?;
    socks5.listen().await?;
    Ok(())
}
