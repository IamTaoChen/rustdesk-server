mod support;
use hbb_common::{bytes::Bytes, protobuf::Message, rendezvous_proto::*, tokio::{self, time::{timeout, Duration}}};

#[tokio::test]
async fn offer_answer_and_trickled_ice_use_live_encrypted_routes() {
    let server = support::Server::start(&[]);
    let mut peer = server.secure(1).await;
    let mut message = RendezvousMessage::new();
    message.set_register_pk(RegisterPk {
        id: "123456789".into(), uuid: Bytes::from_static(&[1; 16]),
        pk: Bytes::from_static(&[2; 32]), ..Default::default()
    });
    peer.send(&message).await.unwrap();
    peer.next().await.unwrap().unwrap();
    let mut controller = server.secure(1).await;
    let key = std::fs::read_to_string(server.directory.path().join("id_ed25519.pub")).unwrap();
    message.set_punch_hole_request(PunchHoleRequest {
        id: "123456789".into(), licence_key: key,
        webrtc_sdp_offer: "webrtc://offer".into(), ..Default::default()
    });
    controller.send(&message).await.unwrap();
    let bytes = timeout(Duration::from_secs(2), peer.next()).await.unwrap().unwrap().unwrap();
    let incoming = RendezvousMessage::parse_from_bytes(&bytes).unwrap();
    let Some(rendezvous_message::Union::PunchHole(punch)) = incoming.union else {
        panic!("SDP offer was replaced by the intranet address path");
    };
    assert_eq!(punch.webrtc_sdp_offer, "webrtc://offer");
    message.set_punch_hole_sent(PunchHoleSent {
        socket_addr: punch.socket_addr.clone(), id: "123456789".into(),
        webrtc_sdp_answer: "webrtc://answer".into(), ..Default::default()
    });
    peer.send(&message).await.unwrap();
    let bytes = timeout(Duration::from_secs(2), controller.next()).await.unwrap().unwrap().unwrap();
    let incoming = RendezvousMessage::parse_from_bytes(&bytes).unwrap();
    let Some(rendezvous_message::Union::PunchHoleResponse(answer)) = incoming.union else { panic!("missing answer"); };
    assert_eq!(answer.webrtc_sdp_answer, "webrtc://answer");
    for candidate in ["candidate:first", "candidate:second"] {
        message.set_ice_candidate(IceCandidate {
            id: "123456789".into(), session_key: "session-one".into(),
            candidate: candidate.into(), ..Default::default()
        });
        controller.send(&message).await.unwrap();
        let bytes = timeout(Duration::from_secs(2), peer.next()).await.unwrap().unwrap().unwrap();
        let incoming = RendezvousMessage::parse_from_bytes(&bytes).unwrap();
        let Some(rendezvous_message::Union::IceCandidate(ice)) = incoming.union else { panic!("missing controller ICE"); };
        assert_eq!(ice.candidate, candidate);
    }
    // The controlled side uses a separate secure TCP connection for its candidates.
    let mut ice_connection = server.secure(1).await;
    message.set_ice_candidate(IceCandidate {
        socket_addr: punch.socket_addr, session_key: "session-one".into(),
        candidate: "candidate:answerer".into(), ..Default::default()
    });
    ice_connection.send(&message).await.unwrap();
    let bytes = timeout(Duration::from_secs(2), controller.next()).await.unwrap().unwrap().unwrap();
    let incoming = RendezvousMessage::parse_from_bytes(&bytes).unwrap();
    let Some(rendezvous_message::Union::IceCandidate(ice)) = incoming.union else { panic!("missing answerer ICE"); };
    assert_eq!(ice.candidate, "candidate:answerer");
}

#[tokio::test]
async fn plaintext_tcp_cannot_submit_sdp() {
    let server = support::Server::start(&[]);
    let mut stream = server.connect().await;
    stream.next().await.unwrap().unwrap(); // consume the server's signed advertisement
    let mut message = RendezvousMessage::new();
    message.set_punch_hole_request(PunchHoleRequest {
        id: "123456789".into(), webrtc_sdp_offer: "webrtc://offer".into(),
        ..Default::default()
    });
    stream.send(&message).await.unwrap();
    let result = timeout(Duration::from_secs(2), stream.next()).await.unwrap();
    assert!(result.is_none() || result.is_some_and(|result| result.is_err()));
}
