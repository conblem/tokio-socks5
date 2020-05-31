use std::iter;
use std::iter::Iterator;
use std::marker::Send;
use std::option::Option;
use std::time::Instant;
use std::sync::Arc;
use std::net::IpAddr;

use tokio;
use tokio::net::TcpStream;
use tokio::task::JoinHandle;
use tokio::sync::RwLock;
use tokio::io::AsyncWriteExt;

use trust_dns_proto::rr::rdata::txt::TXT;
use trust_dns_resolver::TokioAsyncResolver;

use crate::esni::ESNIKeys;
use async_trait::async_trait;
use ttl_cache::TtlCache;

use crate::socks::filter::{Filter, FilterFactory};
use super::tls::{is_client_first, parse_if_tls};

use cookie_factory::{gen_simple, GenError};
use tls_parser::TlsPlaintext;
use tls_parser::serialize::gen_tls_plaintext;
use tokio::net::tcp::{ReadHalf, WriteHalf};


struct ESNIFilter {
    esni_query: Option<JoinHandle<(Instant, Box<dyn Iterator<Item = TXT> + Send + Unpin>)>>,
    cache: Arc<RwLock<TtlCache<IpAddr, ESNIKeys>>>
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
        // todo: maybe better to return result here
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

    async fn pre_data(self: &mut Self, client_read: &mut ReadHalf<'_>, client_write: &mut WriteHalf<'_>, server_read: &mut ReadHalf<'_>, server_write: &mut WriteHalf<'_>) {
        /*let test = match server_read.peer_addr() {
            Ok(peer_addr) => {
                let peer_ip = peer_addr.ip();
                self.cache.read().await.get(&peer_ip).map(Clone::clone)
            },
            Err(_) => None
        };*/

        if !is_client_first(client_read, server_read).await {
            return;
        }
        let mut handshake = vec![];
        let mut tls_plaintext = match parse_if_tls(client_read, &mut handshake).await {
            Some(tls_plaintext) => tls_plaintext,
            None => return
        };

        tls_plaintext.hdr.len = 0;
        let mut test = vec![0; 2000];
        let test_test = &mut test[..];
        let (res, size) = gen_tls_plaintext((test_test, 0), &tls_plaintext).unwrap();
        println!("size {}", size);
        //println!("{:?}", &test[..size]);
        let written = server_write.write(&res[..size]).await;
        println!("written2 {:?}", written);

        //let (_valid_until, txts) = ESNIFilter::post_dns(&mut self.esni_query).await;

        //test.iter().chain(txts);

        /*let txts = txts
            .flat_map(|txt| txt.txt_data().to_vec())
            .flat_map(ESNIKeys::parse)
            .next();

        println!("txts {:?}", txts)*/

        /*match txts.next() {
            Some(txts) => println!("txts {:?}", txts),
            None => {}
        };*/
    }
}

pub(crate) struct ESNIFilterFactory {
    cache: Arc<RwLock<TtlCache<IpAddr, ESNIKeys>>>
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
