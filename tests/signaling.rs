use hbbs::signaling::ServerHandshake;
mod support;
use hbb_common::{
    tokio,
    bytes::{Bytes, BytesMut},
    protobuf::Message,
    rendezvous_proto::{KeyExchange, KxParams},
    sodiumoxide::crypto::{box_, secretbox, sign},
    tcp::{Encrypt, KxTranscript, KX_PARAMS_DOMAIN},
};

fn client_reply(ad: &KeyExchange, signing_pk: &sign::PublicKey, version: u32) -> (KeyExchange, Encrypt) {
    let signed_pk = sign::verify(&ad.keys[0], signing_pk).unwrap();
    let server_pk: [u8; 32] = signed_pk.as_slice().try_into().unwrap();
    let params = sign::verify(&ad.signed_params, signing_pk).unwrap();
    assert!(params.starts_with(KX_PARAMS_DOMAIN));
    let params = KxParams::parse_from_bytes(&params[KX_PARAMS_DOMAIN.len()..]).unwrap();
    assert_eq!(params.pk.as_ref(), signed_pk.as_slice());
    assert_eq!(params.version, 1);
    assert_eq!(server_pk[31] & 0x80, 0x80);
    let (pk, sk) = box_::gen_keypair();
    let key = secretbox::gen_key();
    let sealed = box_::seal(&key.0, &box_::Nonce([0; box_::NONCEBYTES]), &box_::PublicKey(server_pk), &sk);
    let cipher = if version == 0 {
        Encrypt::new(key)
    } else {
        Encrypt::new_split(key, true, &KxTranscript {
            initiator_pk: &pk.0,
            responder_pk: &server_pk,
            advertised: 1,
            picked: version,
        }).unwrap()
    };
    (KeyExchange {
        keys: vec![Bytes::copy_from_slice(&pk.0), sealed.into()],
        version,
        ..Default::default()
    }, cipher)
}

#[test]
fn signed_advertisement_and_legacy_and_v1_bidirectional_messages() {
    let (pk, sk) = sign::gen_keypair();
    for version in [0, 1] {
        let (handshake, ad) = ServerHandshake::start(&sk).unwrap();
        let (reply, mut client) = client_reply(&ad, &pk, version);
        let mut server = handshake.finish(&reply).unwrap();
        for payload in [b"first".as_slice(), b"second", b"third"] {
            let mut received = BytesMut::from(client.enc(payload).as_slice());
            server.dec(&mut received).unwrap();
            assert_eq!(received.as_ref(), payload);
            let mut received = BytesMut::from(server.enc(payload).as_slice());
            client.dec(&mut received).unwrap();
            assert_eq!(received.as_ref(), payload);
        }
    }
}

#[test]
fn each_connection_advertises_a_new_ephemeral_key() {
    let (_, sk) = sign::gen_keypair();
    let (_, first) = ServerHandshake::start(&sk).unwrap();
    let (_, second) = ServerHandshake::start(&sk).unwrap();
    assert_ne!(first.keys, second.keys);
}

#[test]
fn malformed_or_unauthentic_key_exchange_is_rejected() {
    let (pk, sk) = sign::gen_keypair();
    for case in 0..6 {
        let (handshake, ad) = ServerHandshake::start(&sk).unwrap();
        let (mut reply, _) = client_reply(&ad, &pk, 1);
        match case {
            0 => reply.keys.clear(),
            1 => reply.keys[0] = Bytes::from_static(&[0; 31]),
            2 => reply.keys[1] = Bytes::from_static(&[0; 47]),
            3 => reply.keys[1] = Bytes::from_static(&[0; 48]),
            4 => reply.version = 2,
            _ => reply.signed_params = Bytes::from_static(b"unexpected client parameters"),
        }
        assert!(handshake.finish(&reply).is_err(), "case {case}");
    }
}

#[test]
fn sealed_key_from_another_connection_is_rejected() {
    let (pk, sk) = sign::gen_keypair();
    let (_, first_ad) = ServerHandshake::start(&sk).unwrap();
    let (second, _) = ServerHandshake::start(&sk).unwrap();
    let (reply, _) = client_reply(&first_ad, &pk, 1);
    assert!(second.finish(&reply).is_err());
}

#[hbb_common::tokio::test]
async fn server_negotiates_and_answers_encrypted_nat_requests() {
    use hbb_common::rendezvous_proto::{rendezvous_message, RendezvousMessage, TestNatRequest};
    for version in [0, 1] {
        let server = support::Server::start(&[]);
        let mut stream = server.secure(version).await;
        let port = stream.local_addr().port();
        let mut message = RendezvousMessage::new();
        message.set_test_nat_request(TestNatRequest::new());
        stream.send(&message).await.unwrap();
        let bytes = stream.next().await.unwrap().unwrap();
        let response = RendezvousMessage::parse_from_bytes(&bytes).unwrap();
        let Some(rendezvous_message::Union::TestNatResponse(response)) = response.union else {
            panic!("missing encrypted NAT response");
        };
        assert_eq!(response.port, port as i32);
    }
}
