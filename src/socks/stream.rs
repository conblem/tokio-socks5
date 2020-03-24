use std::str;
use std::error::Error;
use std::net::{Ipv4Addr, SocketAddrV4};

use tokio::sync::Mutex;
use tokio::net::TcpStream;
use tokio::join;
use tokio::io::{AsyncReadExt, AsyncWriteExt, Error as IOError, ErrorKind};
use trust_dns_resolver::TokioAsyncResolver;
use std::sync::Arc;

use crate::socks::filter::Filter;

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

pub(super) struct SocksStream {
    pub(super) socket: TcpStream,
    pub(super) resolver: TokioAsyncResolver,
    pub(super) counter: Arc<Mutex<u8>>,
    pub(super) filter: Box<dyn Filter + Send>,
}

impl SocksStream
{
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
        filter: &mut Box<dyn Filter + Send>,
    ) -> Result<Ipv4Addr, Box<dyn Error + Send + Sync>> {
        let fqdn_size = socket.read_u8().await? as usize;
        if fqdn_size > 255 {
            return Err(Box::new(IOError::new(ErrorKind::Other, "domain too long")));
        }

        let mut buf: Vec<u8> = vec![0x00; fqdn_size];
        socket.read_exact(&mut buf).await?;

        let fqdn = str::from_utf8(&buf)?;

        filter.pre_dns(fqdn, resolver).await;

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
            let mut buffer = vec![0; 1500];
            loop {
                match socket_read.read(buffer.as_mut()).await {
                    Err(_) => break,
                    Ok(size) if size == 0 => break,
                    Ok(size) => stream_write.write_all(&buffer[0..size]).await,
                };
            }
            // add error handling
            AsyncWriteExt::shutdown(&mut stream_write).await;
        };

        let from_stream = async move {
            let mut buffer = vec![0; 1500];
            loop {
                match stream_read.read(buffer.as_mut()).await {
                    Err(_) => break,
                    Ok(size) if size == 0 => break,
                    Ok(size) => socket_write.write_all(&buffer[0..size]).await,
                };
            }
            // add error handling
            AsyncWriteExt::shutdown(&mut socket_write).await;
        };

        join!(from_socket, from_stream);
        Ok(())
    }

    pub(super) async fn run(self: &mut Self) -> Result<(), Box<dyn Error + Send + Sync>> {
        let socket = &mut self.socket;
        let resolver = &self.resolver;
        let filter = &mut self.filter;

        let counter = self.counter.clone();
        let counter_two = self.counter.clone();

        let count_up = tokio::spawn(async move {
            let mut counter = counter.lock().await;
            *counter += 1;
            println!("connection open {}", counter);
        });

        SocksStream::resolve_method(socket).await?;
        let dst_addr = match SocksStream::resolve_atyp(socket).await? {
            v5::ATYP_IPV4 => SocksStream::resolve_ipv4(socket).await?,
            v5::ATYP_DOMAIN => {
                SocksStream::resolve_domainame(socket, resolver, filter).await?
            }
            _ => return Err(Box::new(IOError::new(ErrorKind::Other, "invalid atyp"))),
        };
        let mut stream = SocksStream::resolve_socket(socket, dst_addr).await?;
        filter.pre_data(socket, &mut stream).await;
        SocksStream::pipe(socket, stream).await?;

        let count_down = tokio::spawn(async move {
            let mut counter = counter_two.lock().await;
            *counter -= 1;
            println!("connection closed {}", counter);
        });

        count_up.await?;
        count_down.await?;

        Ok(())
    }
}
