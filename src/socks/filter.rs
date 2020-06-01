use std::marker::Send;

use tokio;
use tokio::net::TcpStream;

use trust_dns_resolver::TokioAsyncResolver;

use async_trait::async_trait;


#[async_trait]
pub(crate) trait Filter {
    async fn pre_dns(self: &mut Self, fqdn: &str, resolver: &TokioAsyncResolver);
    async fn pre_data(self: &mut Self, client: &mut TcpStream, server: &mut TcpStream);
}

#[async_trait]
pub(crate) trait FilterFactory
{
    async fn create(self: &mut Self) -> Box<dyn Filter + Send>;
}

