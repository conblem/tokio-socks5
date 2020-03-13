use std::error::Error;
use std::str;
use std::collections::HashMap;
use std::net::{SocketAddrV4, Ipv4Addr};
use std::sync::Arc;

use tokio;
use tokio::join;
use tokio::sync::{RwLock, Mutex};
use tokio::net::{TcpListener, TcpStream};
use tokio::io::{AsyncReadExt, AsyncWriteExt, Error as IOError, ErrorKind};

use trust_dns_resolver::TokioAsyncResolver;
use trust_dns_resolver::config::{ResolverConfig, ResolverOpts};

async fn dns(buf: &[u8], resolver: TokioAsyncResolver) -> Result<Ipv4Addr, Box<dyn Error>> {
    let fqdn = str::from_utf8(buf)?;
    let ips = resolver.ipv4_lookup(fqdn).await?;
    let ip = ips.iter().next();
    match ip {
        Some(ip) => Ok(*ip),
        None => Err(Box::new(IOError::new(ErrorKind::Other, "No ip found"))),
    }
}

async fn method(socket: &mut TcpStream) -> Result<(), Box<dyn Error>> {
    // version
    if socket.read_u8().await? != 0x05 {
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

async fn request(socket: &mut TcpStream, resolver: TokioAsyncResolver) -> Result<TcpStream, Box<dyn Error>> {
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
    let dst_addr = match socket.read_u8().await? {
        0x01 => {
            let mut dst_addr = [0x00; 4];
            socket.read_exact(&mut dst_addr).await?;
            Ipv4Addr::new(dst_addr[0], dst_addr[1], dst_addr[2], dst_addr[3])
        }
        0x03 => {
            let fqdn_size = socket.read_u8().await? as usize;
            if fqdn_size > 255 {
                return Err(Box::new(IOError::new(ErrorKind::Other, "domain too long")))
            }
            let mut fqdn: Vec<u8> = vec![0x00; fqdn_size];
            socket.read_exact(&mut fqdn).await?;
            dns(fqdn.as_ref(), resolver).await?
        }
        _ => return Err(Box::new(IOError::new(ErrorKind::Other, "Address Type mismatch")))
    };
    let dst_port = socket.read_u16().await?;

    let dst = SocketAddrV4::new(
        dst_addr,
        dst_port
    );

    let stream = TcpStream::connect(dst).await?;

    socket.write_all(&[0x05, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]).await?;

    Ok(stream)
}

async fn run(mut socket: TcpStream, mut stream: TcpStream) -> Result<(), Box<dyn Error>> {
    let (mut socket_read, mut socket_write) = socket.split();
    let (mut stream_read, mut stream_write) = stream.split();

    let from_socket = async move {
        let mut buffer = Box::new([0; 2000]);
        loop {
            match socket_read.read(buffer.as_mut()).await {
                Err(_) => break,
                Ok(size) if size == 0 => break,
                Ok(size) => stream_write.write_all(&buffer[0..size]).await
            };
        }
        // add error handling
        AsyncWriteExt::shutdown(&mut stream_write).await;
    };

    let from_stream = async move {
        let mut buffer = Box::new([0; 2000]);
        loop {
            match stream_read.read(buffer.as_mut()).await {
                Err(_) => break,
                Ok(size) if size == 0 => break,
                Ok(size) => socket_write.write_all(&buffer[0..size]).await
            };
        }
        // add error handling
        AsyncWriteExt::shutdown(&mut socket_write).await;
    };


    join!(from_socket, from_stream);
    Ok(())
}

async fn process(mut socket: TcpStream, mut resolver: TokioAsyncResolver, counter: Arc<Mutex<u8>>) -> Result<(), Box<dyn Error>> {
    {
        let mut counter = counter.lock().await;
        *counter += 1;
        println!("counter start {:?}", counter);
    }
    method(&mut socket).await?;
    let stream = request(&mut socket, resolver).await?;
    run(socket, stream).await?;

    {
        let mut counter = counter.lock().await;
        *counter -= 1;
        println!("counter finished {:?}", counter);
    }

    Ok(())
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let mut listener = TcpListener::bind("127.0.0.1:1080").await?;
    let resolver = TokioAsyncResolver::tokio(ResolverConfig::cloudflare_tls(), ResolverOpts::default()).await?;
    let map: Arc<RwLock<HashMap<String, ()>>> = Arc::new(RwLock::new(HashMap::new()));
    let counter = Arc::new(Mutex::new(0));

    loop {
        let (socket, _) = listener.accept().await?;
        let resolver = resolver.clone();
        let counter = counter.clone();

        tokio::spawn(async move {
            process(socket, resolver, counter).await;
        });
    }
    Ok(())
}
