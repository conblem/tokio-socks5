use std::sync::Arc;
use std::error::Error;

use tokio::sync::{Mutex};
use tokio::net::TcpListener;

use trust_dns_resolver::TokioAsyncResolver;
use trust_dns_resolver::config::{ResolverConfig, ResolverOpts};

mod stream;
use stream::SocksStream;

pub(crate) mod filter;
use filter::FilterFactory;

pub(crate) struct SocksListener<'a>
{
    listener: TcpListener,
    resolver: TokioAsyncResolver,
    counter: Arc<Mutex<u8>>,
    filter_factory: Box<dyn FilterFactory + 'a>
}

impl <'a> SocksListener<'a>
{
    pub(crate) async fn new<F: FilterFactory + 'a>(filter_factory: F) -> Result<SocksListener<'a>, Box<dyn Error + Send + Sync>> {
        let listener = TcpListener::bind("127.0.0.1:1080").await?;
        let resolver =
            TokioAsyncResolver::tokio(ResolverConfig::cloudflare_tls(), ResolverOpts::default())
                .await?;
        let counter = Arc::new(Mutex::new(0));
        let filter_factory = Box::new(filter_factory);

        Ok(SocksListener {
            listener,
            resolver,
            counter,
            filter_factory
        })
    }

    pub(crate) async fn listen(self: &mut Self) -> Result<(), Box<dyn Error + Send + Sync>> {
        loop {
            let (socket, _) = self.listener.accept().await?;
            let resolver = self.resolver.clone();
            let counter = self.counter.clone();
            let filter = self.filter_factory.create().await;

            tokio::spawn(async move {
                let mut stream = SocksStream {
                    socket,
                    resolver,
                    counter,
                    filter
                };
                stream.run().await
            });
        }
    }
}
