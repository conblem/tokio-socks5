use tokio;
use std::error::Error;
use tokio::net::{TcpListener, TcpStream};
use tokio::io::{AsyncReadExt, AsyncWriteExt, copy, Error as IOError, ErrorKind};
use std::net::{SocketAddrV4, Ipv4Addr};
use std::io::BufRead;
use tokio::task::JoinHandle;
use tokio::join;
use std::net::Shutdown;

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

async fn request(socket: &mut TcpStream) -> Result<TcpStream, Box<dyn Error>> {
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
    if socket.read_u8().await? != 0x01 {
        return Err(Box::new(IOError::new(ErrorKind::Other, "Address Type mismatch")));
    }
    let mut dst_addr = [0x00; 4];
    socket.read_exact(&mut dst_addr).await?;
    let dst_port = socket.read_u16().await?;

    let dst = SocketAddrV4::new(
        Ipv4Addr::new(dst_addr[0], dst_addr[1], dst_addr[2], dst_addr[3]),
        dst_port
    );

    let mut stream = TcpStream::connect(dst).await?;

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
                Err(e) => break,
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
                Err(e) => break,
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

async fn process(mut socket: TcpStream) -> Result<(), Box<dyn Error>> {
    method(&mut socket).await?;
    let stream = request(&mut socket).await?;
    run(socket, stream).await?;
    println!("request finished");


    Ok(())
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let mut listener = TcpListener::bind("127.0.0.1:1080").await?;

    loop {
        let (socket, _) = listener.accept().await?;

        tokio::spawn(async move {
            println!("request");
            // Process each socket concurrently.
            process(socket).await;
        });
    }
    Ok(())
}
