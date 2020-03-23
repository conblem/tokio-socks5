use tls_parser::tls::parse_tls_plaintext;
use tls_parser::tls::TlsMessage::Handshake;
use tls_parser::tls::TlsMessageHandshake::ClientHello;
use tls_parser::tls::TlsVersion;

{
let socket_read_peek = async {
let mut buf = [1];
socket_read.peek(&mut buf).await;
true
};
let stream_read_peek = async {
let mut buf = [1];
stream_read.peek(&mut buf).await;
false
};
let race_result = race(socket_read_peek, stream_read_peek).await.unwrap_or(false);
println!("race {}", race_result);

//let tls_13_record_header: [u8; 3] = [0x16, 0x03, 0x01];
let mut record_header = [0; 5];
socket_read.peek(&mut record_header).await;
println!("size {:?}", record_header);
let handshake_size = match record_header {
[0x16, 0x03, 0x01, size @ ..] => u16::from_be_bytes(size) + 5,
_ => 0
};
if handshake_size != 0 {
println!("size {}", handshake_size);
let mut handshake = vec![0; handshake_size as usize];
socket_read.peek(&mut handshake[..]).await;
let (_, mut tls) = parse_tls_plaintext(&handshake).unwrap();
let is_tls_13= tls.msg.into_iter().find(|msg| {
let msg = match msg {
Handshake(msg) => msg,
_ => return false
};
match msg {
ClientHello(msg) => {
println!("version {:?}", msg.version);
msg.version == TlsVersion::Tls13
},
_ => false
}
}).is_some();
println!("is tls 1.3 {}", is_tls_13);
}
}
