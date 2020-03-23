use std::future::Future;
use std::iter;
use std::marker::Send;
use std::option::Option;

use tokio;
use tokio::net::TcpStream;
use tokio::task::JoinHandle;

use trust_dns_proto::rr::rdata::txt::TXT;
use trust_dns_resolver::TokioAsyncResolver;

use async_trait::async_trait;

#[async_trait]
pub trait Filter {
    async fn pre_dns(self: &mut Self, fqdn: &str, resolver: &TokioAsyncResolver);
    async fn post_dns(self: &mut Self);
    async fn pre_data(self: &mut Self, client: &mut TcpStream, server: &mut TcpStream);
}

struct ESNIFilter {
    esni_query: Option<JoinHandle<Box<dyn Iterator<Item = TXT> + Send + Unpin>>>,
}

#[async_trait]
impl Filter for ESNIFilter {
    async fn pre_dns(self: &mut Self, fqdn: &str, resolver: &TokioAsyncResolver) {
        let resolver = resolver.clone();
        let fqdn = fqdn.to_owned();
        let esni_query = tokio::spawn(async move {
            let txts = resolver.txt_lookup(fqdn).await;
            match txts {
                Ok(txts) => Box::new(txts.into_iter()),
                Err(_) => Box::new(iter::empty()) as Box<dyn Iterator<Item = TXT> + Send + Unpin>,
            }
        });

        self.esni_query = Some(esni_query);
    }

    async fn post_dns(self: &mut Self) {
        let esni_query = &mut self.esni_query.as_mut();
        let txts = match esni_query {
            Some(esni_query) => esni_query.await,
            None => return,
        };
        let mut txts = match txts {
            Ok(txts) => txts,
            Err(_) => return,
        };

        txts.next();
    }

    async fn pre_data(self: &mut Self, client: &mut TcpStream, server: &mut TcpStream) {
        unimplemented!()
    }
}

pub(crate) async fn create_esni_filter() -> Box<dyn Filter> {
    Box::new(ESNIFilter { esni_query: None })
}
