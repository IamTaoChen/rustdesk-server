//! Server-side rendezvous key exchange, compatible with official legacy and v1 clients.
use hbb_common::{
    bail,
    bytes::Bytes,
    protobuf::Message,
    rendezvous_proto::{KeyExchange, KxParams},
    sodiumoxide::crypto::{box_, sign},
    tcp::{Encrypt, KxTranscript, KX_PARAMS_DOMAIN, KX_VERSION_LATEST},
    ResultType,
};

/// Decode untrusted address metadata without the shared legacy decoder's unchecked arithmetic.
pub(crate) fn decode_addr(bytes: &[u8]) -> Option<std::net::SocketAddr> {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
    let addr = if bytes.len() == 18 {
        let ip: [u8; 16] = bytes[..16].try_into().ok()?;
        SocketAddr::new(IpAddr::V6(Ipv6Addr::from(ip)), u16::from_le_bytes([bytes[16], bytes[17]]))
    } else {
        if bytes.is_empty() || bytes.len() > 16 { return None; }
        let mut padded = [0; 16]; padded[..bytes.len()].copy_from_slice(bytes);
        let number = u128::from_le_bytes(padded);
        let time = (number >> 17) & u32::MAX as u128;
        let ip = u32::try_from((number >> 49).checked_sub(time)?).ok()?;
        let port = u16::try_from((number & 0x1ffff).checked_sub(time & 0xffff)?).ok()?;
        SocketAddr::new(IpAddr::V4(Ipv4Addr::from(ip.to_le_bytes())), port)
    };
    if addr.port() == 0 || addr.ip().is_unspecified() || addr.ip().is_multicast() { None } else { Some(hbb_common::try_into_v4(addr)) }
}

#[cfg(test)]
mod address_tests {
    use super::*;
    #[test]
    fn address_metadata_roundtrips_and_malformed_arithmetic_is_rejected() {
        for address in ["192.0.2.1:1", "127.0.0.1:65535", "[2001:db8::1]:1234"] {
            let address = address.parse().unwrap();
            for _ in 0..100 { assert_eq!(decode_addr(&hbb_common::AddrMangle::encode(address)), Some(address)); }
        }
        for bytes in [vec![], vec![1], vec![255; 16], vec![1; 17], vec![0; 18], vec![0; 19]] { assert_eq!(decode_addr(&bytes), None); }
    }
}

pub struct ServerHandshake {
    public_key: [u8; box_::PUBLICKEYBYTES],
    secret_key: box_::SecretKey,
}

impl ServerHandshake {
    pub fn start(signing_key: &sign::SecretKey) -> ResultType<(Self, KeyExchange)> {
        let (mut public_key, secret_key) = box_::gen_keypair();
        // The official client uses this otherwise-unused X25519 bit to require signed params.
        public_key.0[31] |= 0x80;
        let params = KxParams {
            pk: Bytes::copy_from_slice(&public_key.0),
            version: KX_VERSION_LATEST,
            ..Default::default()
        };
        let mut signed = KX_PARAMS_DOMAIN.to_vec();
        signed.extend(params.write_to_bytes()?);
        let advertisement = KeyExchange {
            keys: vec![sign::sign(&public_key.0, signing_key).into()],
            version: KX_VERSION_LATEST,
            signed_params: sign::sign(&signed, signing_key).into(),
            ..Default::default()
        };
        Ok((Self { public_key: public_key.0, secret_key }, advertisement))
    }

    // Consuming the state prevents a second exchange from resetting the stream counters.
    pub fn finish(self, reply: &KeyExchange) -> ResultType<Encrypt> {
        if reply.keys.len() != 2 || !reply.signed_params.is_empty() {
            bail!("Invalid client key exchange message");
        }
        if reply.version > KX_VERSION_LATEST {
            bail!("Unsupported key exchange version");
        }
        if reply.keys[0].len() != box_::PUBLICKEYBYTES || reply.keys[1].len() != 48 {
            bail!("Invalid key exchange key lengths");
        }
        let key = Encrypt::decode(&reply.keys[1], &reply.keys[0], &self.secret_key)?;
        match reply.version {
            0 => Ok(Encrypt::new(key)),
            1 => Encrypt::new_split(key, false, &KxTranscript {
                initiator_pk: &reply.keys[0],
                responder_pk: &self.public_key,
                advertised: KX_VERSION_LATEST,
                picked: reply.version,
            }),
            _ => bail!("Unsupported key exchange version"),
        }
    }
}
