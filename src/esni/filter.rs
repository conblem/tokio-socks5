use std::iter;
use std::iter::Iterator;
use std::marker::Send;
use std::option::Option;
use std::time::Instant;
use std::sync::Arc;

use tokio;
use tokio::net::TcpStream;
use tokio::task::JoinHandle;
use tokio::sync::RwLock;

use trust_dns_proto::rr::rdata::txt::TXT;
use trust_dns_resolver::TokioAsyncResolver;

use crate::esni::ESNIKeys;
use async_trait::async_trait;
use ttl_cache::TtlCache;

use crate::socks::filter::{Filter, FilterFactory};


struct ESNIFilter {
    esni_query: Option<JoinHandle<(Instant, Box<dyn Iterator<Item = TXT> + Send + Unpin>)>>,
    cache: Arc<RwLock<TtlCache<String, ()>>>
}

impl ESNIFilter {
    async fn post_dns(
        esni_query: &mut Option<
            JoinHandle<(Instant, Box<dyn Iterator<Item = TXT> + Send + Unpin>)>,
        >,
    ) -> (Instant, Box<dyn Iterator<Item = TXT> + Send + Unpin>) {
        let esni_query = esni_query.as_mut();
        let join_result = match esni_query {
            Some(esni_query) => esni_query.await,
            None => return (Instant::now(), Box::new(iter::empty())),
        };

        match join_result {
            Ok((valid_until, txts)) => (valid_until, txts),
            Err(_) => (Instant::now(), Box::new(iter::empty())),
        }
    }
}

#[async_trait]
impl Filter for ESNIFilter {
    async fn pre_dns(self: &mut Self, fqdn: &str, resolver: &TokioAsyncResolver) {
        let resolver = resolver.clone();
        let esni_fqdn = format!("_esni.{}", fqdn);
        let esni_query = tokio::spawn(async move {
            let txts = resolver.txt_lookup(esni_fqdn).await;
            match txts {
                Ok(txts) => {
                    let valid_until = txts.valid_until();
                    let txts =
                        Box::new(txts.into_iter()) as Box<dyn Iterator<Item = TXT> + Send + Unpin>;
                    (valid_until, txts)
                }
                Err(_) => {
                    let valid_until = Instant::now();
                    let txts =
                        Box::new(iter::empty()) as Box<dyn Iterator<Item = TXT> + Send + Unpin>;
                    (valid_until, txts)
                }
            }
        });

        self.esni_query = Some(esni_query);
    }

    async fn pre_data(self: &mut Self, _client: &mut TcpStream, _server: &mut TcpStream) {
        let (_valid_until, txts) = ESNIFilter::post_dns(&mut self.esni_query).await;

        let txts = txts
            .flat_map(|txt| txt.txt_data().to_vec())
            .flat_map(ESNIKeys::parse)
            .next();

        println!("txts {:?}", txts)

        /*match txts.next() {
            Some(txts) => println!("txts {:?}", txts),
            None => {}
        };*/
    }
}

pub(crate) struct ESNIFilterFactory {
    cache: Arc<RwLock<TtlCache<String, ()>>>
}

impl ESNIFilterFactory {
    pub(crate) fn new() -> Self {
        ESNIFilterFactory {
            cache: Arc::new(RwLock::new(TtlCache::new(1000))),
        }
    }
}

#[async_trait]
impl FilterFactory for ESNIFilterFactory {
    async fn create(self: &mut Self) -> Box<dyn Filter + Send> {
        let cache = self.cache.clone();
        Box::new(ESNIFilter { esni_query: None, cache })
    }
}
