use tokio::net::TcpStream;

use crate::race::race;

use tls_parser::tls::TlsVersion;
use tls_parser::tls::TlsMessage::Handshake;
use tls_parser::tls::TlsMessageHandshake::ClientHello;
use tls_parser::{TlsPlaintext, parse_tls_plaintext, TlsMessage};
use tls_parser::tls_extensions::{TlsExtension, parse_tls_extensions};
use tls_parser::tls_extensions::TlsExtension::SupportedVersions;
use std::slice::Iter;

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
    race(client_peek, server_peek).await.unwrap_or(false)
}


fn find_tls_13_extension<'a>(ext: &'a TlsExtension<'a>) -> Option<&'a TlsExtension<'a>> {
    let mut tls_versions: Iter<TlsVersion> = match ext {
        SupportedVersions(tls_versions) => tls_versions.iter(),
        _ => return None
    };


    match tls_versions.find(|tls_version| *tls_version == &TlsVersion::Tls13) {
        Some(_) => Some(ext),
        None => None
    }
}

fn find_tls_13_handshake<'a>(msg: &'a TlsMessage<'a>) -> Option<&'a TlsMessage<'a>> {
    let msg_handshake = match msg {
        Handshake(msg) => msg,
        _ => return None
    };

    let client_hello_contents = match msg_handshake {
        ClientHello(client_hello_contents) => client_hello_contents,
        _ => return None
    };

    let ext = match client_hello_contents.ext {
        Some(ext) => ext,
        None => return None
    };

    let ext = match parse_tls_extensions(ext) {
        Ok((_, ext)) => ext,
        Err(_) => return None
    };

    if ext.iter().find_map(find_tls_13_extension).is_none() {
        return None
    }

    Some(msg)
}

pub(super) async fn parse_if_tls(client: &mut TcpStream) -> Option<TlsPlaintext<'_>> {
    let mut record_header = [0; 5];
    client.peek(&mut record_header).await;

    let handshake_size = match record_header {
        [0x16, 0x03, 0x01, size @ ..] => u16::from_be_bytes(size) + 5,
        _ => return None
    };

    let mut handshake = vec![0; handshake_size as usize];

    client.peek(&mut handshake[..]).await;
    let (_, mut tls) = parse_tls_plaintext(&handshake).unwrap();

    {
        let msg = &mut tls.msg;
        let is_tls13 = msg.iter().find_map(find_tls_13_handshake);
        if is_tls13.is_none() {
            return None;
        }
    }

    let test = tls.clone();
    None
}
