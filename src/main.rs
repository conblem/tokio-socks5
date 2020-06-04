use std::error::Error;

use tokio;

mod race;

mod socks;
use socks::SocksListener;

mod esni;
use esni::filter::ESNIFilterFactory;
use esni::ESNIKeys;

const esni_test: &str =
    "/wG/eiFaACQAHQAgCxHg1Et/IrzXkIPnGHYRnQpFfdGTDxXWJknscKczByQAAhMBAQQAAAAAXtJm4AAAAABe2k/gAAA=";

fn main() {
    println!("started");

    let mut keys = ESNIKeys::parse(esni_test).unwrap();
    keys.test();
    println!("{:?}", keys);
}

//#[tokio::main]
async fn main_test() -> Result<(), Box<dyn Error + Send + Sync>> {

    let filter_factory = ESNIFilterFactory::new();
    let mut socks = SocksListener::new(filter_factory).await?;
    socks.listen().await?;
    Ok(())
}
