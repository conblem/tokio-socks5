use std::error::Error;
use std::io::Read;

use tokio;

mod socks5;
use socks5::Socks5Listener;

mod race;

use rustls::internal::msgs::codec::Reader;
use rustls::internal::msgs::codec::Codec;
use rustls::internal::msgs::handshake::KeyShareEntries;
use rustls::internal::msgs::enums::CipherSuite;

use ring::digest::digest;
use ring::digest::SHA256;

use byteorder::{ReadBytesExt, BigEndian};

use base64;


#[tokio::main]
async fn main() -> Result<(), Box<dyn Error + Send + Sync>> {
    let esni = "/wHndGGZACQAHQAgNvYgGft2eIBZ33NG8uc9+UFtmSTA/kK+ZdTvleiZ01sAAhMBAQQAAAAAXnBnYAAAAABeeFBgAAA=";
    let esni = base64::decode(esni).expect("invalid base64");
    let mut esni = &esni[..];

    let _version = esni.read_u16::<BigEndian>()?;

    let mut checksum = [0; 4];
    esni.read_exact(&mut checksum)?;
    let _calculated_checksum = digest(&SHA256, esni);

    let mut keyshare_entry_size = [0; 2];
    keyshare_entry_size.copy_from_slice(&esni[..2]);
    let keyshare_entry_size = u16::from_be_bytes(keyshare_entry_size) as usize;

    let mut keyshare_entry = vec![0; keyshare_entry_size + 2];
    esni.read_exact(&mut keyshare_entry)?;
    let mut reader = Reader::init(&keyshare_entry);
    let _keyshare_entries = KeyShareEntries::read(&mut reader).expect("keyshare");

    let ciphersuite_size = esni.read_u16::<BigEndian>()? as usize;
    let mut ciphersuite = vec![0; ciphersuite_size];
    esni.read_exact(&mut ciphersuite)?;
    let mut reader = Reader::init(&ciphersuite);
    let _ciphersuite = CipherSuite::read(&mut reader).expect("ciphersuite");

    let _padded_lenght = esni.read_u16::<BigEndian>()?;
    let _not_before = esni.read_u64::<BigEndian>()?;
    let _not_after = esni.read_u64::<BigEndian>()?;

    let _extension_size = esni.read_u16::<BigEndian>()?;

    println!("start");
    let mut socks5 = Socks5Listener::new().await?;
    socks5.listen().await?;
    Ok(())
}
