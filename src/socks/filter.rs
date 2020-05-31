use std::marker::Send;

use tokio;
use tokio::net::tcp::{ReadHalf, WriteHalf};

use trust_dns_resolver::TokioAsyncResolver;

use async_trait::async_trait;


#[async_trait]
pub(crate) trait Filter {
    async fn pre_dns(self: &mut Self, fqdn: &str, resolver: &TokioAsyncResolver);
    async fn pre_data(self: &mut Self, client_read: &mut ReadHalf<'_>, client_write: &mut WriteHalf<'_>, server_read: &mut ReadHalf<'_>, server_write: &mut WriteHalf<'_>);
}

#[async_trait]
pub(crate) trait FilterFactory
{
    async fn create(self: &mut Self) -> Box<dyn Filter + Send>;
}

