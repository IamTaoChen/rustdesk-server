mod support;
use hbb_common::{
    bytes::Bytes,
    protobuf::Message,
    rendezvous_proto::{rendezvous_message, register_pk_response, OnlineRequest, RegisterPk, RendezvousMessage},
    tcp::FramedStream,
    tokio::{self, time::{timeout, Duration}},
};

pub async fn register(stream: &mut FramedStream, id: &str) {
    let mut message = RendezvousMessage::new();
    message.set_register_pk(RegisterPk {
        id: id.to_owned(), uuid: Bytes::from_static(&[1; 16]),
        pk: Bytes::from_static(&[2; 32]), ..Default::default()
    });
    stream.send(&message).await.unwrap();
    let bytes = timeout(Duration::from_secs(2), stream.next()).await.unwrap().unwrap().unwrap();
    let message = RendezvousMessage::parse_from_bytes(&bytes).unwrap();
    let Some(rendezvous_message::Union::RegisterPkResponse(response)) = message.union else {
        panic!("missing registration response");
    };
    assert_eq!(response.result.enum_value().unwrap(), register_pk_response::Result::OK);
}

async fn online(server: &support::Server, id: &str) -> bool {
    let mut stream = server.secure(1).await;
    let mut message = RendezvousMessage::new();
    message.set_online_request(OnlineRequest {
        peers: vec![id.to_owned()], ..Default::default()
    });
    stream.send(&message).await.unwrap();
    let bytes = stream.next().await.unwrap().unwrap();
    let response = RendezvousMessage::parse_from_bytes(&bytes).unwrap();
    let Some(rendezvous_message::Union::OnlineResponse(response)) = response.union else {
        panic!("missing online response");
    };
    response.states[0] & 0x80 != 0
}

#[tokio::test]
async fn tcp_registration_heartbeat_and_disconnect_update_online_status() {
    let server = support::Server::start(&[]);
    let mut stream = server.secure(1).await;
    register(&mut stream, "123456789").await;
    assert!(online(&server, "123456789").await);
    let heartbeat = timeout(Duration::from_secs(18), stream.next()).await.unwrap().unwrap().unwrap();
    assert!(heartbeat.is_empty());
    stream.send_bytes(Bytes::new()).await.unwrap();
    assert!(online(&server, "123456789").await);
    drop(stream);
    for _ in 0..30 {
        if !online(&server, "123456789").await { return; }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    panic!("closed connection remained online");
}

#[tokio::test]
async fn websocket_registers_without_udp() {
    use hbb_common::futures_util::{SinkExt, StreamExt};
    let server = support::Server::start(&[]);
    drop(server.connect().await);
    let (mut ws, _) = tokio_tungstenite::connect_async(format!("ws://127.0.0.1:{}", server.port + 2)).await.unwrap();
    let mut message = RendezvousMessage::new();
    message.set_register_pk(RegisterPk {
        id: "987654321".to_owned(), uuid: Bytes::from_static(&[3; 16]),
        pk: Bytes::from_static(&[4; 32]), ..Default::default()
    });
    ws.send(tungstenite::Message::Binary(message.write_to_bytes().unwrap().into())).await.unwrap();
    let bytes = ws.next().await.unwrap().unwrap().into_data();
    let message = RendezvousMessage::parse_from_bytes(&bytes).unwrap();
    let Some(rendezvous_message::Union::RegisterPkResponse(response)) = message.union else {
        panic!("missing WebSocket registration response");
    };
    assert_eq!(response.result.enum_value().unwrap(), register_pk_response::Result::OK);
    assert!(online(&server, "987654321").await);
}

#[tokio::test]
async fn registered_tcp_peer_and_controller_exchange_relay_messages() {
    use hbb_common::rendezvous_proto::{RelayResponse, RequestRelay};
    let server = support::Server::start(&[]);
    let mut peer = server.secure(1).await;
    register(&mut peer, "123456789").await;
    let mut controller = server.secure(1).await;
    let mut message = RendezvousMessage::new();
    message.set_request_relay(RequestRelay {
        id: "123456789".to_owned(), uuid: "test-relay-session".to_owned(),
        ..Default::default()
    });
    controller.send(&message).await.unwrap();
    let bytes = timeout(Duration::from_secs(2), peer.next()).await.unwrap().unwrap().unwrap();
    let response = RendezvousMessage::parse_from_bytes(&bytes).unwrap();
    let Some(rendezvous_message::Union::RequestRelay(request)) = response.union else {
        panic!("relay request was not routed to registered TCP peer");
    };
    assert_eq!(request.uuid, "test-relay-session");
    let mut reply = RendezvousMessage::new();
    reply.set_relay_response(RelayResponse {
        socket_addr: request.socket_addr,
        uuid: "test-relay-session".to_owned(), relay_server: "relay.example".to_owned(),
        socket_addr_v6: hbb_common::AddrMangle::encode("[2001:db8::1]:1234".parse().unwrap()).into(),
        ..Default::default()
    });
    peer.send(&reply).await.unwrap();
    let bytes = timeout(Duration::from_secs(2), controller.next()).await.unwrap().unwrap().unwrap();
    let response = RendezvousMessage::parse_from_bytes(&bytes).unwrap();
    assert!(matches!(response.union, Some(rendezvous_message::Union::RelayResponse(response)) if response.socket_addr_v6.is_empty()));
    assert!(online(&server, "123456789").await);
    // A relay reply must not tear down the registered peer's persistent connection.
    let mut query = RendezvousMessage::new();
    query.set_online_request(OnlineRequest { peers: vec!["123456789".into()], ..Default::default() });
    peer.send(&query).await.unwrap();
    let bytes = timeout(Duration::from_secs(2), peer.next()).await.unwrap().unwrap().unwrap();
    assert!(matches!(RendezvousMessage::parse_from_bytes(&bytes).unwrap().union, Some(rendezvous_message::Union::OnlineResponse(_))));
}

#[tokio::test]
async fn registered_connection_receives_followup_registration_queries_and_proxy_errors() {
    use hbb_common::rendezvous_proto::*;
    let server = support::Server::start(&[]);
    let mut stream = server.secure(1).await;
    register(&mut stream, "123456789").await;
    register(&mut stream, "123456789").await;
    let mut message = RendezvousMessage::new();
    message.set_test_nat_request(TestNatRequest::new());
    stream.send(&message).await.unwrap();
    let bytes = timeout(Duration::from_secs(2), stream.next()).await.unwrap().unwrap().unwrap();
    assert!(matches!(RendezvousMessage::parse_from_bytes(&bytes).unwrap().union, Some(rendezvous_message::Union::TestNatResponse(_))));
    message.set_http_proxy_request(HttpProxyRequest { method: "GET".into(), path: "/api/version".into(), ..Default::default() });
    stream.send(&message).await.unwrap();
    let bytes = timeout(Duration::from_secs(2), stream.next()).await.unwrap().unwrap().unwrap();
    assert!(matches!(RendezvousMessage::parse_from_bytes(&bytes).unwrap().union, Some(rendezvous_message::Union::HttpProxyResponse(response)) if response.status == 503));
    message.set_online_request(OnlineRequest { peers: vec!["123456789".into()], ..Default::default() });
    stream.send(&message).await.unwrap();
    let bytes = timeout(Duration::from_secs(2), stream.next()).await.unwrap().unwrap().unwrap();
    assert!(matches!(RendezvousMessage::parse_from_bytes(&bytes).unwrap().union, Some(rendezvous_message::Union::OnlineResponse(response)) if response.states[0] == 0x80));
}

#[tokio::test]
async fn unsolicited_signal_replies_cannot_inject_into_a_registered_session() {
    use hbb_common::{AddrMangle, rendezvous_proto::*};
    let server = support::Server::start(&[]);
    let mut victim = server.secure(1).await;
    register(&mut victim, "123456789").await;
    let address = Bytes::from(AddrMangle::encode(victim.local_addr()));
    let mut replies = Vec::new();
    let mut message = RendezvousMessage::new();
    message.set_relay_response(RelayResponse { socket_addr: address.clone(), uuid: "unsolicited".into(), relay_server: "relay.example".into(), ..Default::default() }); replies.push(message);
    let mut message = RendezvousMessage::new();
    message.set_punch_hole_sent(PunchHoleSent { socket_addr: address.clone(), id: "123456789".into(), ..Default::default() }); replies.push(message);
    let mut message = RendezvousMessage::new();
    message.set_local_addr(LocalAddr { socket_addr: address, id: "123456789".into(), ..Default::default() }); replies.push(message);
    for message in replies {
        let mut attacker = server.secure(1).await;
        attacker.send(&message).await.unwrap();
        assert!(timeout(Duration::from_millis(150), victim.next()).await.is_err());
    }
    assert!(online(&server, "123456789").await);
}

#[tokio::test]
async fn relay_ipv6_metadata_is_validated_and_legacy_empty_ack_stays_compatible() {
    use hbb_common::{AddrMangle, rendezvous_proto::*};
    let server = support::Server::start(&[("ENABLE_IPV6_PUNCH", "Y")]);
    let mut peer = server.secure(1).await;
    register(&mut peer, "123456789").await;
    let mut controller = server.secure(1).await;
    let mut message = RendezvousMessage::new();
    message.set_request_relay(RequestRelay { id: "123456789".into(), uuid: "ipv6-relay".into(), ..Default::default() });
    controller.send(&message).await.unwrap();
    let bytes = timeout(Duration::from_secs(2), peer.next()).await.unwrap().unwrap().unwrap();
    let Some(rendezvous_message::Union::RequestRelay(request)) = RendezvousMessage::parse_from_bytes(&bytes).unwrap().union else { panic!("missing request"); };
    let valid = Bytes::from(AddrMangle::encode("[2001:db8::1]:1234".parse().unwrap()));
    for metadata in [Bytes::from_static(&[1]), Bytes::from(AddrMangle::encode("[ff02::1]:1234".parse().unwrap())), Bytes::from(AddrMangle::encode("[fe80::1]:1234".parse().unwrap())), valid.clone()] {
        message.set_relay_response(RelayResponse { socket_addr: request.socket_addr.clone(), socket_addr_v6: metadata.clone(), ..Default::default() });
        peer.send(&message).await.unwrap();
        let bytes = timeout(Duration::from_secs(2), controller.next()).await.unwrap().unwrap().unwrap();
        let Some(rendezvous_message::Union::RelayResponse(response)) = RendezvousMessage::parse_from_bytes(&bytes).unwrap().union else { panic!("missing response"); };
        assert_eq!(response.socket_addr_v6, if metadata == valid { valid.clone() } else { Bytes::new() });
    }
}
