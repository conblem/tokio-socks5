use std::error::Error;
use std::net::{Ipv4Addr, SocketAddrV4};
use std::str;

use tokio;
use tokio::io::{AsyncReadExt, AsyncWriteExt, Error as IOError, ErrorKind};
use tokio::join;
use tokio::net::{TcpListener, TcpStream};

use std::ops::AddAssign;
use tokio::sync::mpsc::{unbounded_channel, UnboundedSender};
use tokio::task::JoinHandle;
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
    socket: TcpStream,
    resolver: TokioAsyncResolver,
    sender: UnboundedSender<ConnectionCount>,
}

impl Socks5Stream {
    async fn resolve_method(socket: &mut TcpStream) -> Result<(), Box<dyn Error + Send + Sync>> {
        // version
        if socket.read_u8().await? != v5::VERSION {
            return Ok(());
        }
        let method_size = socket.read_u8().await? as usize;
        if method_size < 0x01 || method_size > 0xFF {
            return Ok(());
        }
        let mut method: Vec<u8> = vec![0x00; method_size];
        socket.read_exact(&mut method).await?;
        if method[0] != 0x00 {
            socket.write_all(&[0x05, 0xFF]).await?;
            return Ok(());
        }

        socket.write_all(&[0x05, 0x00]).await?;

        Ok(())
    }

    async fn resolve_atyp(socket: &mut TcpStream) -> Result<u8, Box<dyn Error + Send + Sync>> {
        // ver
        if socket.read_u8().await? != 0x05 {
            return Err(Box::new(IOError::new(ErrorKind::Other, "Version mismatch")));
        }
        // cmd
        if socket.read_u8().await? != 0x01 {
            return Err(Box::new(IOError::new(ErrorKind::Other, "Command mismatch")));
        }
        // rsv
        socket.read_u8().await?;
        // atyp
        Ok(socket.read_u8().await?)
    }

    async fn resolve_ipv4(
        socket: &mut TcpStream,
    ) -> Result<Ipv4Addr, Box<dyn Error + Send + Sync>> {
        let mut dst_addr = [0x00; 4];
        socket.read_exact(&mut dst_addr).await?;
        Ok(Ipv4Addr::new(
            dst_addr[0],
            dst_addr[1],
            dst_addr[2],
            dst_addr[3],
        ))
    }

    async fn resolve_domainame(
        socket: &mut TcpStream,
        resolver: &TokioAsyncResolver,
    ) -> Result<Ipv4Addr, Box<dyn Error + Send + Sync>> {
        let fqdn_size = socket.read_u8().await? as usize;
        if fqdn_size > 255 {
            return Err(Box::new(IOError::new(ErrorKind::Other, "domain too long")));
        }

        let mut buf: Vec<u8> = vec![0x00; fqdn_size];
        socket.read_exact(&mut buf).await?;

        let fqdn = str::from_utf8(&buf)?;
        println!("domain resolved {}", fqdn);
        let ips = resolver.ipv4_lookup(fqdn).await?;
        let ip = ips.iter().next();
        match ip {
            Some(ip) => Ok(*ip),
            None => Err(Box::new(IOError::new(ErrorKind::Other, "No ip found"))),
        }
    }

    async fn resolve_socket(
        socket: &mut TcpStream,
        dst_addr: Ipv4Addr,
    ) -> Result<TcpStream, Box<dyn Error + Send + Sync>> {
        let dst_port = socket.read_u16().await?;

        let dst = SocketAddrV4::new(dst_addr, dst_port);

        let stream = TcpStream::connect(dst).await?;

        socket
            .write_all(&[0x05, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00])
            .await?;

        Ok(stream)
    }

    async fn pipe(
        socket: &mut TcpStream,
        mut stream: TcpStream,
    ) -> Result<(), Box<dyn Error + Send + Sync>> {
        let (mut socket_read, mut socket_write) = socket.split();
        let (mut stream_read, mut stream_write) = stream.split();

        let from_socket = async move {
            let mut buffer = Box::new([0; 2000]);
            loop {
                match socket_read.read(buffer.as_mut()).await {
                    Err(_) => break,
                    Ok(size) if size == 0 => break,
                    Ok(size) => stream_write.write_all(&buffer[0..size]).await,
                };
            }
        };

        let from_stream = async move {
            let mut buffer = Box::new([0; 2000]);
            loop {
                match stream_read.read(buffer.as_mut()).await {
                    Err(_) => break,
                    Ok(size) if size == 0 => break,
                    Ok(size) => socket_write.write_all(&buffer[0..size]).await,
                };
            }
        };

        join!(from_socket, from_stream);
        Ok(())
    }

    async fn run(mut self) -> Result<(), Box<dyn Error + Send + Sync>> {
        let socket = &mut self.socket;
        let resolver = &self.resolver;

        Socks5Stream::resolve_method(socket).await?;
        let dst_addr = match Socks5Stream::resolve_atyp(socket).await? {
            v5::ATYP_IPV4 => Socks5Stream::resolve_ipv4(socket).await?,
            v5::ATYP_DOMAIN => Socks5Stream::resolve_domainame(socket, resolver).await?,
            _ => return Err(Box::new(IOError::new(ErrorKind::Other, "invalid atyp"))),
        };
        let stream = Socks5Stream::resolve_socket(socket, dst_addr).await?;
        Socks5Stream::pipe(socket, stream).await?;

        Ok(())
    }
}

pub struct Socks5Listener {
    listener: TcpListener,
    resolver: TokioAsyncResolver,
    receiver: JoinHandle<()>,
    sender: UnboundedSender<ConnectionCount>,
}

enum ConnectionCount {
    Increase,
    Decrease,
}

impl AddAssign<ConnectionCount> for u8 {
    fn add_assign(&mut self, rhs: ConnectionCount) {
        match rhs {
            ConnectionCount::Increase => *self += 1,
            ConnectionCount::Decrease => *self -= 1,
        }
    }
}

impl Socks5Listener {
    pub(crate) async fn new() -> Result<Self, Box<dyn Error + Send + Sync>> {
        let listener = TcpListener::bind("127.0.0.1:1080").await?;
        let resolver =
            TokioAsyncResolver::tokio(ResolverConfig::cloudflare_tls(), ResolverOpts::default())?;
        let (sender, mut receiver) = unbounded_channel();
        let receiver = tokio::spawn(async move {
            let mut count = 0;
            while let Some(val) = receiver.recv().await {
                count += val;
                println!("Connections {}", count);
            }
        });

        Ok(Socks5Listener {
            listener,
            resolver,
            receiver,
            sender,
        })
    }

    pub(crate) async fn listen(self: &mut Self) -> Result<(), Box<dyn Error + Send + Sync>> {
        loop {
            let (socket, _) = self.listener.accept().await?;
            let resolver = self.resolver.clone();
            let sender = self.sender.clone();

            tokio::spawn(
                Socks5Stream {
                    socket,
                    resolver,
                    sender,
                }
                .run(),
            );
        }
    }
}
