#![allow(dead_code)]
use hbb_common::{
    bytes::Bytes,
    protobuf::Message,
    rendezvous_proto::{rendezvous_message, KeyExchange, RendezvousMessage},
    sodiumoxide::crypto::{box_, secretbox, sign},
    tcp::{FramedStream, KxTranscript},
    tokio::time::{sleep, timeout, Duration, Instant},
};
use std::{net::TcpListener, process::{Child, Command, Stdio}};

pub struct Server {
    child: Child,
    pub directory: tempfile::TempDir,
    pub port: u16,
}

impl Server {
    pub fn start(extra_env: &[(&str, &str)]) -> Self {
        let port = loop {
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let port = listener.local_addr().unwrap().port();
            if port > 2 && port < u16::MAX - 2 {
                if let (Ok(_nat), Ok(_ws)) = (
                    TcpListener::bind(("127.0.0.1", port - 1)),
                    TcpListener::bind(("127.0.0.1", port + 2)),
                ) { break port; }
            }
        };
        let directory = tempfile::tempdir().unwrap();
        let child = Command::new(env!("CARGO_BIN_EXE_hbbs"))
            .args(["-b", "127.0.0.1", "-p", &port.to_string()])
            .env("TEST_HBBS", "no")
            .env("RUST_LOG", "error")
            .envs(extra_env.iter().copied())
            .current_dir(directory.path())
            .stdout(Stdio::null()).stderr(Stdio::null())
            .spawn().unwrap();
        Self { child, directory, port }
    }

    pub async fn connect(&self) -> FramedStream {
        let until = Instant::now() + Duration::from_secs(10);
        loop {
            if let Ok(stream) = FramedStream::new(&format!("127.0.0.1:{}", self.port), None, 500).await {
                return stream;
            }
            assert!(Instant::now() < until, "server did not start");
            sleep(Duration::from_millis(20)).await;
        }
    }

    pub async fn secure(&self, version: u32) -> FramedStream {
        let mut stream = self.connect().await;
        let bytes = timeout(Duration::from_secs(2), stream.next()).await.unwrap().unwrap().unwrap();
        let advertisement = RendezvousMessage::parse_from_bytes(&bytes).unwrap();
        let Some(rendezvous_message::Union::KeyExchange(ad)) = advertisement.union else {
            panic!("server did not advertise key exchange");
        };
        let pk = std::fs::read_to_string(self.directory.path().join("id_ed25519.pub")).unwrap();
        let pk = base64::decode(pk).unwrap();
        let signed_pk = sign::verify(&ad.keys[0], &sign::PublicKey::from_slice(&pk).unwrap()).unwrap();
        let public_key = box_::PublicKey::from_slice(&signed_pk).unwrap();
        let (pk, sk) = box_::gen_keypair();
        let key = secretbox::gen_key();
        let sealed = box_::seal(&key.0, &box_::Nonce([0; box_::NONCEBYTES]), &public_key, &sk);
        let mut reply = RendezvousMessage::new();
        reply.set_key_exchange(KeyExchange {
            keys: vec![Bytes::copy_from_slice(&pk.0), sealed.into()], version,
            ..Default::default()
        });
        stream.send(&reply).await.unwrap();
        if version == 0 { stream.set_key(key); } else {
            stream.set_key_split(key, true, &KxTranscript {
                initiator_pk: &pk.0, responder_pk: &signed_pk,
                advertised: ad.version, picked: version,
            }).unwrap();
        }
        stream
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}
