use std::error::Error;
use std::net::{Ipv4Addr, SocketAddrV4};
use std::ops::AddAssign;
use std::str;
use tokio;
use tokio::io::{copy_bidirectional, AsyncReadExt, AsyncWriteExt, Error as IOError, ErrorKind};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc::{unbounded_channel, UnboundedSender};
use tokio::sync::watch;
use tokio::{select, try_join};
use tracing::{debug, debug_span, error, info, info_span, Instrument};
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
    client: TcpStream,
    resolver: TokioAsyncResolver,
    counter: UnboundedSender<ConnectionCount>,
    stopper: watch::Receiver<()>,
}

impl Drop for Socks5Stream {
    fn drop(&mut self) {
        match self.counter.send(ConnectionCount::Decrease) {
            Ok(_) => {}
            Err(e) => info!("Not possible to count connections, {}", e),
        }
    }
}

impl Socks5Stream {
    fn new(
        client: TcpStream,
        resolver: TokioAsyncResolver,
        counter: UnboundedSender<ConnectionCount>,
        stopper: watch::Receiver<()>,
    ) -> Self {
        match counter.send(ConnectionCount::Increase) {
            Ok(_) => {}
            Err(e) => info!("Not possible to count connections, {}", e),
        };

        Socks5Stream {
            client,
            resolver,
            counter,
            stopper,
        }
    }

    // currently no way to access errors from inner
    async fn run(mut self) -> Result<(), Box<dyn Error + Send + Sync>> {
        let client = &mut self.client;
        let resolver = &self.resolver;
        let stopper = &mut self.stopper;

        let inner = async {
            resolve_method(client).await?;
            let dst_addr = match resolve_atyp(client).await? {
                v5::ATYP_IPV4 => resolve_ipv4(client).await?,
                v5::ATYP_DOMAIN => resolve_domainame(client, resolver).await?,
                _ => Err(Box::new(IOError::new(ErrorKind::Other, "invalid atyp")))?,
            };
            let server = resolve_socket(client, dst_addr).await?;
            Ok(server) as Result<_, Box<dyn Error + Send + Sync>>
        };

        let mut server = select! {
            server = inner => {
                match server {
                    Ok(server) => server,
                    Err(e) => {
                        client.shutdown().await;
                        return Err(e)
                    }
                }
            }
            _ = stopper.changed() => {
                client.shutdown().await?;
                return Ok(())
            }
        };

        let res = select! {
            res = pipe(client, &mut server) => res,
            _ = stopper.changed() => Ok(()),
        };

        let shutdown = try_join!(client.shutdown(), server.shutdown());

        // first return earlier error after attempted shutdown
        res?;
        shutdown?;

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
    let mut method = vec![0x00; method_size];
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

async fn pipe(
    client: &mut TcpStream,
    server: &mut TcpStream,
) -> Result<(), Box<dyn Error + Send + Sync>> {
    copy_bidirectional(client, server).await?;

    Ok(())
}

pub struct Socks5Listener {
    resolver: TokioAsyncResolver,
    stopper: (watch::Sender<()>, watch::Receiver<()>),
    counter: UnboundedSender<ConnectionCount>,
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

        let (counter, mut receiver) = unbounded_channel();

        let stopper = watch::channel(());
        tokio::spawn(
            async move {
                let mut count = 0;
                while let Some(val) = receiver.recv().await {
                    count += val;
                    info!("{} Connections", count);
                }
                info!("{} closing", count);
            }
            .instrument(info_span!("counter")),
        );

        Ok(Socks5Listener {
            resolver,
            counter,
            stopper,
        })
    }

    pub(crate) async fn listen(self: &mut Self) -> Result<(), Box<dyn Error + Send + Sync>> {
        let listener = TcpListener::bind("127.0.0.1:1080").await?;

        loop {
            let (stream, addr) = listener.accept().await?;
            let resolver = self.resolver.clone();
            let counter = self.counter.clone();
            let stopper = self.stopper.1.clone();

            tokio::spawn(
                async move {
                    let stream = Socks5Stream::new(stream, resolver, counter, stopper);
                    let err = match stream.run().await {
                        Ok(_) => return,
                        Err(err) => err,
                    };

                    error!("{}", err);
                }
                .instrument(debug_span!("conn", %addr)),
            );
        }
    }
}
