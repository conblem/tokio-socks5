use std::error::Error;
use std::net::{Ipv4Addr, SocketAddrV4};
use std::ops::AddAssign;
use std::str;
use tokio;
use tokio::io::{copy, AsyncReadExt, AsyncWriteExt, Error as IOError, ErrorKind};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc::error::SendError;
use tokio::sync::mpsc::{unbounded_channel, UnboundedSender};
use tokio::task::JoinHandle;
use tokio::try_join;
use tracing::{debug, debug_span, info, info_span, Instrument};
use trust_dns_resolver::config::{ResolverConfig, ResolverOpts};
use trust_dns_resolver::TokioAsyncResolver;

#[allow(dead_code)]
mod v5 {
    pub const VERSION: u8 = 0x05;

    pub const METH_NO_AUTH: u8 = 0x00;

    pub const CMD_CONNECT: u8 = 0x00;

    pub const ATYP_IPV4: u8 = 0x01;
    pub const ATYP_IPV6: u8 = 0x04;
    pub const ATYP_DOMAIN: u8 = 0x03;

    pub const REPLY_SUCCEEDED: u8 = 0x00;
    pub const REPLY_GENERAL_FAILURE: u8 = 0x01;
    pub const REPLY_NOT_ALLOWED: u8 = 0x02;
    pub const REPLY_NETWORK_UNREACHABLE: u8 = 0x03;
    pub const REPLY_HOST_UNREACHABLE: u8 = 0x04;
    pub const REPLY_CONNECTION_REFUSED: u8 = 0x05;
    pub const REPLY_TTL_EXPIRED: u8 = 0x06;
    pub const REPLY_CMD_UNSUPPORTED: u8 = 0x07;
    pub const REPLY_ATYP_UNSUPPORTED: u8 = 0x08;
}

struct Socks5Stream {
    client: Option<TcpStream>,
    resolver: TokioAsyncResolver,
    sender: UnboundedSender<ConnectionCount>,
}

impl Drop for Socks5Stream {
    fn drop(&mut self) {
        match self.sender.send(ConnectionCount::Decrease) {
            Ok(_) => {}
            Err(e) => info!("Not possible to count connections, {}", e),
        }
    }
}

impl Socks5Stream {
    fn new(
        client: TcpStream,
        resolver: TokioAsyncResolver,
        sender: UnboundedSender<ConnectionCount>,
    ) -> Self {
        match sender.send(ConnectionCount::Increase) {
            Ok(_) => {}
            Err(e) => info!("Not possible to count connections, {}", e),
        };

        Socks5Stream {
            client: Some(client),
            resolver,
            sender,
        }
    }

    async fn run(mut self) -> Result<(), Box<dyn Error + Send + Sync>> {
        let mut client = self.client.take().unwrap();
        let resolver = &self.resolver;

        resolve_method(&mut client).await?;
        let dst_addr = match resolve_atyp(&mut client).await? {
            v5::ATYP_IPV4 => resolve_ipv4(&mut client).await?,
            v5::ATYP_DOMAIN => resolve_domainame(&mut client, resolver).await?,
            _ => return Err(Box::new(IOError::new(ErrorKind::Other, "invalid atyp"))),
        };
        let server = resolve_socket(&mut client, dst_addr).await?;
        pipe(client, server).await?;

        Ok(())
    }
}

async fn resolve_method(client: &mut TcpStream) -> Result<(), Box<dyn Error + Send + Sync>> {
    // version
    if client.read_u8().await? != v5::VERSION {
        return Ok(());
    }
    let method_size = client.read_u8().await? as usize;
    if method_size < 0x01 || method_size > 0xFF {
        return Ok(());
    }
    let mut method: Vec<u8> = vec![0x00; method_size];
    client.read_exact(&mut method).await?;
    if method[0] != 0x00 {
        client.write_all(&[0x05, 0xFF]).await?;
        return Ok(());
    }

    client.write_all(&[0x05, 0x00]).await?;

    Ok(())
}

async fn resolve_atyp(client: &mut TcpStream) -> Result<u8, Box<dyn Error + Send + Sync>> {
    // ver
    if client.read_u8().await? != 0x05 {
        return Err(Box::new(IOError::new(ErrorKind::Other, "Version mismatch")));
    }
    // cmd
    if client.read_u8().await? != 0x01 {
        return Err(Box::new(IOError::new(ErrorKind::Other, "Command mismatch")));
    }
    // rsv
    client.read_u8().await?;
    // atyp
    Ok(client.read_u8().await?)
}

async fn resolve_ipv4(client: &mut TcpStream) -> Result<Ipv4Addr, Box<dyn Error + Send + Sync>> {
    let dst_addr = client.read_u32().await?;
    Ok(dst_addr.into())
}

async fn resolve_domainame(
    client: &mut TcpStream,
    resolver: &TokioAsyncResolver,
) -> Result<Ipv4Addr, Box<dyn Error + Send + Sync>> {
    let fqdn_size = client.read_u8().await? as usize;
    if fqdn_size > 255 {
        return Err(Box::new(IOError::new(ErrorKind::Other, "domain too long")));
    }

    let mut buf = vec![0x00; fqdn_size];
    client.read_exact(&mut buf).await?;
    let fqdn = str::from_utf8(&buf)?;
    debug!("Looked up domain {}", fqdn);

    let ips = resolver.ipv4_lookup(fqdn).await?;
    match ips.iter().next() {
        Some(ip) => Ok(*ip),
        None => Err(Box::new(IOError::new(ErrorKind::Other, "No ip found"))),
    }
}

async fn resolve_socket(
    client: &mut TcpStream,
    dst_addr: Ipv4Addr,
) -> Result<TcpStream, Box<dyn Error + Send + Sync>> {
    let dst_port = client.read_u16().await?;

    let dst = SocketAddrV4::new(dst_addr, dst_port);

    let server = TcpStream::connect(dst).await?;

    client
        .write_all(&[0x05, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00])
        .await?;

    Ok(server)
}

async fn pipe(client: TcpStream, server: TcpStream) -> Result<(), Box<dyn Error + Send + Sync>> {
    let (mut client_read, mut client_write) = client.into_split();
    let (mut server_read, mut server_write) = server.into_split();

    let from_client = tokio::spawn(async move {
        copy(&mut client_read, &mut server_write).await?;
        server_write.shutdown().await?;

        Ok(()) as Result<(), Box<dyn Error + Send + Sync>>
    });

    let from_server = tokio::spawn(async move {
        copy(&mut server_read, &mut client_write).await?;
        client_write.shutdown().await?;

        Ok(()) as Result<(), Box<dyn Error + Send + Sync>>
    });

    from_client.await??;
    from_server.await??;

    Ok(())
}

pub struct Socks5Listener {
    resolver: TokioAsyncResolver,
    receiver: JoinHandle<()>,
    sender: UnboundedSender<ConnectionCount>,
}

enum ConnectionCount {
    Increase,
    Decrease,
}

impl AddAssign<ConnectionCount> for i8 {
    fn add_assign(&mut self, rhs: ConnectionCount) {
        match rhs {
            ConnectionCount::Increase => *self += 1,
            ConnectionCount::Decrease => *self -= 1,
        }
    }
}

impl Socks5Listener {
    pub(crate) fn new() -> Result<Self, Box<dyn Error + Send + Sync>> {
        let resolver =
            TokioAsyncResolver::tokio(ResolverConfig::cloudflare_tls(), ResolverOpts::default())?;

        let (sender, mut receiver) = unbounded_channel();
        let receiver = tokio::spawn(
            async move {
                let mut count = 0;
                while let Some(val) = receiver.recv().await {
                    count += val;
                    info!("{} Connections", count);
                }
            }
            .instrument(info_span!("counter")),
        );

        Ok(Socks5Listener {
            resolver,
            receiver,
            sender,
        })
    }

    pub(crate) async fn listen(self: &mut Self) -> Result<(), Box<dyn Error + Send + Sync>> {
        let listener = TcpListener::bind("127.0.0.1:1080").await?;

        loop {
            let (stream, addr) = listener.accept().await?;
            let resolver = self.resolver.clone();
            let sender = self.sender.clone();

            tokio::spawn(
                async move {
                    let stream = Socks5Stream::new(stream, resolver, sender);
                    stream.run().await
                }
                .instrument(debug_span!("conn", %addr)),
            );
        }
    }
}
