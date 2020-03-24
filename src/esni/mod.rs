use std::io;
use std::io::BufRead;
use std::io::Read;
use std::time::Duration;
use std::vec::Vec;

use rustls::internal::msgs::codec::{Codec, Reader};
use rustls::internal::msgs::enums::CipherSuite;
use rustls::internal::msgs::handshake::KeyShareEntries;

use byteorder::{BigEndian, ReadBytesExt};

use ring::digest::digest;
use ring::digest::SHA256;

use base64;
use std::time::{SystemTime, UNIX_EPOCH};

pub(crate) mod filter;

#[derive(Debug)]
pub(crate) struct ESNIKeys {
    keys: KeyShareEntries,
    ciphersuites: Vec<CipherSuite>,
    padded_length: u16,
}

impl ESNIKeys {
    fn version_is_draft2(esni: &[u8]) -> bool {
        if esni.len() < 2 {
            return false;
        }

        let mut version = [0; 2];
        version.copy_from_slice(&esni[..2]);
        u16::from_be_bytes(version) == 0xff01
    }

    fn checksum(esni: &[u8]) -> bool {
        if esni.len() < 6 {
            return false;
        }

        let mut checksum = [0; 4];
        checksum.copy_from_slice(&esni[2..6]);

        let mut copy = vec![0; esni.len()];
        copy.copy_from_slice(esni);

        copy[2] = 0;
        copy[3] = 0;
        copy[4] = 0;
        copy[5] = 0;

        let hash = digest(&SHA256, &copy);

        &esni[2..6] == &hash.as_ref()[..4]
    }

    fn keyshare_entries(esni: &mut &[u8]) -> io::Result<KeyShareEntries> {
        if esni.len() < 2 {
            return Err(io::Error::new(io::ErrorKind::Other, "to short"));
        }

        let mut keyshare_entry_size = [0; 2];
        keyshare_entry_size.copy_from_slice(&esni[..2]);
        let keyshare_entry_size = u16::from_be_bytes(keyshare_entry_size) as usize;

        let mut keyshare_entry = vec![0; keyshare_entry_size + 2];
        esni.read_exact(&mut keyshare_entry)?;
        let mut reader = Reader::init(&keyshare_entry);
        Ok(KeyShareEntries::read(&mut reader).expect("keyshare"))
    }

    fn ciphersuites(esni: &mut &[u8]) -> io::Result<Vec<CipherSuite>> {
        let ciphersuite_size = esni.read_u16::<BigEndian>()? as usize;
        let mut ciphersuite = vec![0; ciphersuite_size];
        esni.read_exact(&mut ciphersuite)?;
        let mut reader = Reader::init(&ciphersuite);

        let mut ciphersuites = vec![];
        while reader.any_left() {
            match CipherSuite::read(&mut reader) {
                Some(cs) => ciphersuites.push(cs),
                None => {
                    return Err(io::Error::new(
                        io::ErrorKind::Other,
                        "could not read ciphersuite",
                    ))
                }
            }
        }
        Ok(ciphersuites)
    }

    fn time(mut esni: &[u8]) -> io::Result<()> {
        let now = SystemTime::now();

        let not_before = Duration::from_secs(esni.read_u64::<BigEndian>()?);
        let not_before = UNIX_EPOCH
            .checked_add(not_before)
            .ok_or_else(|| io::Error::new(io::ErrorKind::Other, "not before wrong"))?;

        let not_after = Duration::from_secs(esni.read_u64::<BigEndian>()?);
        let not_after = UNIX_EPOCH
            .checked_add(not_after)
            .ok_or_else(|| io::Error::new(io::ErrorKind::Other, "not after wrong"))?;

        if now < not_before {
            return Err(io::Error::new(io::ErrorKind::Other, "to early"));
        }
        if now > not_after {
            return Err(io::Error::new(io::ErrorKind::Other, "to late"));
        }

        Ok(())
    }

    pub(crate) fn parse<T: AsRef<[u8]>>(txt: T) -> Option<Self> {
        println!("start parse");
        let esni = match base64::decode(txt).ok() {
            Some(txt) => txt,
            None => return None,
        };
        let mut esni = &esni[..];

        if !ESNIKeys::version_is_draft2(esni) {
            return None;
        }
        if !ESNIKeys::checksum(esni) {
            return None;
        }

        //remove version and checksum for further processing
        esni.consume(6);

        let keys = match ESNIKeys::keyshare_entries(&mut esni) {
            Err(_) => return None,
            Ok(k) => k,
        };

        let ciphersuites = match ESNIKeys::ciphersuites(&mut esni) {
            Err(_) => return None,
            Ok(cs) => cs,
        };

        let padded_length = match esni.read_u16::<BigEndian>() {
            Err(_) => return None,
            Ok(p) => p,
        };

        if ESNIKeys::time(esni).is_err() {
            return None;
        }

        Some(ESNIKeys {
            keys,
            ciphersuites,
            padded_length,
        })
    }
}
