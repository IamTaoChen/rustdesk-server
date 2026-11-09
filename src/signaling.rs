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
