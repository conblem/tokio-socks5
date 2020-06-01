use tokio::io::AsyncReadExt;
use tokio::net::TcpStream;

use crate::race::race;

use tls_parser::tls::TlsVersion;
use tls_parser::tls::TlsMessage::Handshake;
use tls_parser::tls::TlsMessageHandshake::ClientHello;
use tls_parser::{TlsPlaintext, parse_tls_plaintext, TlsMessage};
use tls_parser::tls_extensions::{TlsExtension, parse_tls_extensions};
use tls_parser::tls_extensions::TlsExtension::SupportedVersions;
use std::slice::Iter;

use byteorder::{BigEndian, WriteBytesExt};

pub(super) async fn is_client_first(client: &mut TcpStream, server: &mut TcpStream) -> bool {
    let client_peek = async {
        let mut buf = [1];
        client.peek(&mut buf).await;
        true
    };
    let server_peek = async {
        let mut buf = [1];
        server.peek(&mut buf).await;
        false
    };
    race(client_peek, server_peek, false).await
}


fn find_tls_13_extension<'a>(ext: &'a TlsExtension<'a>) -> bool {
    let mut tls_versions: Iter<TlsVersion> = match ext {
        SupportedVersions(tls_versions) => tls_versions.iter(),
        _ => return false
    };


    match tls_versions.find(|tls_version| **tls_version == TlsVersion::Tls13) {
        Some(_) => true,
        None => false
    }
}

fn find_tls_13_handshake<'a>(msg: &'a TlsMessage<'a>) -> bool {
    let msg_handshake = match msg {
        Handshake(msg) => msg,
        _ => return false
    };

    let client_hello_contents = match msg_handshake {
        ClientHello(client_hello_contents) => client_hello_contents,
        _ => return false
    };

    let exts = match client_hello_contents.ext {
        Some(exts) => exts,
        None => return false
    };

    let exts = match parse_tls_extensions(exts) {
        Ok((_, exts)) => exts,
        Err(_) => return false
    };

    if exts.iter().find(|ext| find_tls_13_extension(ext)).is_none() {
        return false
    }

    true
}

pub(super) async fn parse_if_tls<'a>(client: &mut TcpStream, handshake: &'a mut Vec<u8>) -> Option<TlsPlaintext<'a>> {
    let mut record_header = [0; 5];
    client.peek(&mut record_header).await;

    let handshake_size = match record_header {
        [0x16, 0x03, 0x01, size @ ..] => u16::from_be_bytes(size) + 5,
        _ => return None
    } as usize;

    handshake.resize(handshake_size, 0);
    client.peek(&mut handshake[..handshake_size]).await;
    let mut tls = parse_tls_plaintext(handshake).unwrap().1;
    let msg = &mut tls.msg;
    let is_tls13 = msg.iter().find(|msg| find_tls_13_handshake(msg));
    if is_tls13.is_none() {
        return None;
    }

    let mut noop = vec![0; handshake_size];
    client.read_exact(&mut noop[..handshake_size]).await;
    //println!("{:?}", &noop[..handshake_size]);

    Some(tls)
}
