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
    let bytes = stream.next().await.unwrap().unwrap();
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
        ..Default::default()
    });
    peer.send(&reply).await.unwrap();
    let bytes = timeout(Duration::from_secs(2), controller.next()).await.unwrap().unwrap().unwrap();
    let response = RendezvousMessage::parse_from_bytes(&bytes).unwrap();
    assert!(matches!(response.union, Some(rendezvous_message::Union::RelayResponse(_))));
}
