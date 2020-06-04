use std::io;
use std::io::Read;
use std::io::{BufRead, Write};
use std::time::Duration;
use std::vec::Vec;

use rustls::internal::msgs::codec::{Codec, Reader};
use rustls::internal::msgs::enums::CipherSuite;
use rustls::internal::msgs::handshake::KeyShareEntries;

use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};

use ring::digest::digest;
use ring::digest::SHA256;
use ring::{agreement, rand};

use base64;
use rustls::internal::msgs::base::{PayloadU16, PayloadU8};
use std::time::{SystemTime, UNIX_EPOCH};

pub(crate) mod filter;
mod tls;

/*
 * HKDF-Expand-Label(Secret, Label, Context, Length) =
 * HKDF-Expand(Secret, HkdfLabel, Length)
 *
 * Where HkdfLabel is specified as:
 *
 * struct {
 *     uint16 length = Length;
 *     opaque label<7..255> = "tls13 " + Label;
 *     opaque context<0..255> = Context;
 * } HkdfLabel;
 */

struct HkdfLabel<'a> {
    label: &'a str,
    context: &'a [u8],
}

impl<'a> HkdfLabel<'a> {
    fn new(label: &'a str, context: &'a [u8]) -> Option<Self> {
        match (label.len(), context.len()) {
            (label_len, _) if label_len < 7 => return None,
            (label_len, _) if label_len > 255 => return None,
            (_, context_len) if context_len > 255 => return None,
            (_, _) => Some(HkdfLabel { label, context }),
        }
    }
}

impl<'a> From<HkdfLabel<'a>> for Vec<u8> {
    fn from(hkdf_label: HkdfLabel<'a>) -> Self {
        let label = hkdf_label.label;
        let context = hkdf_label.context;

        let label = format!("tls13 {}", hkdf_label.label);
        let label = label.as_bytes();

        // todo: safe conversions
        let label_length = label.len() as u8;
        let context_length = context.len() as u8;
        let hkdf_label_length = (label_length + context_length + 4) as u16;

        let mut hkdf_label = vec![];

        hkdf_label
            .write_u16::<BigEndian>(hkdf_label_length)
            .unwrap();

        hkdf_label.write_u8(label_length).unwrap();
        hkdf_label.write_all(label).unwrap();

        hkdf_label.write_u8(context_length);
        hkdf_label.write_all(context).unwrap();

        hkdf_label
    }
}

fn expandLabel(prk: &ring::hkdf::Prk) {}

#[derive(Debug, Clone)]
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

    pub(crate) fn test(self: &mut Self) {
        let hallo = &self.keys.get(0).unwrap().payload.0;
        let peer_public_key = agreement::UnparsedPublicKey::new(&agreement::X25519, &hallo);

        let rng = rand::SystemRandom::new();
        let my_private_key =
            agreement::EphemeralPrivateKey::generate(&agreement::X25519, &rng).unwrap();

        let mut material = [0; 32];

        agreement::agree_ephemeral(
            my_private_key,
            &peer_public_key,
            ring::error::Unspecified,
            |key_material| {
                material.copy_from_slice(key_material);
                Ok(())
            },
        )
        .unwrap();

        let prk = ring::hkdf::Salt::new(ring::hkdf::HKDF_SHA384, &[]).extract(&material);
        println!("{:?}", prk);
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

#[cfg(test)]
mod test {
    use crate::esni::HkdfLabel;
    use byteorder::{BigEndian, ReadBytesExt};
    use std::error::Error;
    use std::io::{Cursor, Read};

    const EXPECTED_LABEL_LENGTH: u8 = 14;
    const EXPECTED_CONTEXT_LENGTH: u8 = 4;
    const EXPECTED_HKDF_LABEL_LENGTH: u16 = 22;

    #[test]
    fn hkdf_label() -> Result<(), Box<dyn Error>> {
        let context = [1, 1, 1, 1];
        let hkdf_label = HkdfLabel::new("esni key", &context).unwrap();
        let mut hkdf_label = Cursor::new(Vec::from(hkdf_label));

        assert_eq!(
            hkdf_label.read_u16::<BigEndian>()?,
            EXPECTED_HKDF_LABEL_LENGTH
        );

        let label_length = hkdf_label.read_u8()?;
        assert_eq!(label_length, EXPECTED_LABEL_LENGTH);

        let mut label = vec![0; EXPECTED_LABEL_LENGTH as usize];
        hkdf_label.read(&mut label)?;
        let label = String::from_utf8(label)?;
        assert_eq!("tls13 esni key", &label);

        let context_length = hkdf_label.read_u8()?;
        assert_eq!(context_length, EXPECTED_CONTEXT_LENGTH);

        let mut context = [0; EXPECTED_CONTEXT_LENGTH as usize];
        hkdf_label.read(&mut context)?;
        assert_eq!(&context, &[1, 1, 1, 1]);

        Ok(())
    }

    #[test]
    fn valid_hkdf_label() {
        let context = [1, 0, 1, 0];
        let long_context = [1; 256];

        let label = "esni key";
        let empty_label = "";
        let mut long_label = String::new();
        for x in 0..256 {
            long_label.push('x');
        }

        let hkdf_label = HkdfLabel::new(&long_label, &context);
        assert!(hkdf_label.is_none());

        let hkdf_label = HkdfLabel::new(&empty_label, &context);
        assert!(hkdf_label.is_none());

        let hkdf_label = HkdfLabel::new(&label, &long_context);
        assert!(hkdf_label.is_none());

        let hkdf_label = HkdfLabel::new(&long_label, &long_context);
        assert!(hkdf_label.is_none());

        let hkdf_label = HkdfLabel::new(&empty_label, &long_context);
        assert!(hkdf_label.is_none());

        let hkdf_label = HkdfLabel::new(&label, &context);
        assert!(hkdf_label.is_some());
    }
}
