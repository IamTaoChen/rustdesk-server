mod support;
use hbb_common::{bytes::Bytes, protobuf::Message, rendezvous_proto::*, tokio::{self, net::UdpSocket, time::{timeout, Duration}}, AddrMangle};

async fn receive(socket: &UdpSocket) -> RendezvousMessage {
    let mut buffer = [0; 65536];
    let size = timeout(Duration::from_secs(2), socket.recv(&mut buffer)).await.unwrap().unwrap();
    RendezvousMessage::parse_from_bytes(&buffer[..size]).unwrap()
}

#[tokio::test]
async fn opt_in_udp_nat_and_correlated_punch_reply_preserve_ports_and_ipv6() {
    let server = support::Server::start(&[("ENABLE_UDP_PUNCH", "Y"), ("ENABLE_IPV6_PUNCH", "Y")]);
    let mut controller = server.secure(1).await;
    let destination = format!("127.0.0.1:{}", server.port);
    let controller_udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let peer_udp = UdpSocket::bind("127.0.0.2:0").await.unwrap();
    let mut message = RendezvousMessage::new();
    message.set_test_nat_request(TestNatRequest::new());
    controller_udp.send_to(&message.write_to_bytes().unwrap(), &destination).await.unwrap();
    let nat = receive(&controller_udp).await;
    let Some(rendezvous_message::Union::TestNatResponse(nat)) = nat.union else { panic!("missing UDP NAT response"); };
    assert_eq!(nat.port, controller_udp.local_addr().unwrap().port() as i32);
    message.set_register_pk(RegisterPk {
        id: "987654321".into(), uuid: Bytes::from_static(&[3; 16]),
        pk: Bytes::from_static(&[4; 32]), ..Default::default()
    });
    peer_udp.send_to(&message.write_to_bytes().unwrap(), &destination).await.unwrap();
    let registered = receive(&peer_udp).await;
    assert!(matches!(registered.union, Some(rendezvous_message::Union::RegisterPkResponse(_))));
    let controller_v6 = "[2001:db8::1]:12345".parse().unwrap();
    let peer_v6 = "[2001:db8::2]:23456".parse().unwrap();
    message.set_punch_hole_request(PunchHoleRequest {
        id: "987654321".into(),
        licence_key: std::fs::read_to_string(server.directory.path().join("id_ed25519.pub")).unwrap(),
        udp_port: controller_udp.local_addr().unwrap().port() as i32,
        socket_addr_v6: AddrMangle::encode(controller_v6).into(),
        ..Default::default()
    });
    controller.send(&message).await.unwrap();
    let punch = receive(&peer_udp).await;
    let Some(rendezvous_message::Union::PunchHole(punch)) = punch.union else { panic!("missing introduction"); };
    assert_eq!(punch.udp_port, controller_udp.local_addr().unwrap().port() as i32);
    assert_eq!(AddrMangle::decode(&punch.socket_addr_v6), controller_v6);
    message.set_punch_hole_sent(PunchHoleSent {
        id: "wrong-peer".into(), socket_addr: punch.socket_addr.clone(),
        ..Default::default()
    });
    peer_udp.send_to(&message.write_to_bytes().unwrap(), &destination).await.unwrap();
    assert!(timeout(Duration::from_millis(120), controller_udp.recv(&mut [0; 2048])).await.is_err());
    message.set_punch_hole_sent(PunchHoleSent {
        id: "987654321".into(), socket_addr: punch.socket_addr,
        socket_addr_v6: AddrMangle::encode(peer_v6).into(), ..Default::default()
    });
    peer_udp.send_to(&message.write_to_bytes().unwrap(), &destination).await.unwrap();
    let response = receive(&controller_udp).await;
    let Some(rendezvous_message::Union::PunchHoleResponse(response)) = response.union else { panic!("missing UDP response"); };
    assert!(response.is_udp);
    assert_eq!(AddrMangle::decode(&response.socket_addr), peer_udp.local_addr().unwrap());
    assert_eq!(AddrMangle::decode(&response.socket_addr_v6), peer_v6);
    let bytes = controller.next().await.unwrap().unwrap();
    assert!(matches!(RendezvousMessage::parse_from_bytes(&bytes).unwrap().union, Some(rendezvous_message::Union::PunchHoleResponse(_))));
    // A completed pending request cannot be reused as an ongoing reflector.
    peer_udp.send_to(&message.write_to_bytes().unwrap(), &destination).await.unwrap();
    assert!(timeout(Duration::from_millis(120), controller_udp.recv(&mut [0; 2048])).await.is_err());
}

#[tokio::test]
async fn udp_punch_stays_disabled_by_default() {
    let server = support::Server::start(&[]);
    drop(server.connect().await);
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let mut message = RendezvousMessage::new();
    message.set_test_nat_request(TestNatRequest::new());
    socket.send_to(&message.write_to_bytes().unwrap(), format!("127.0.0.1:{}", server.port)).await.unwrap();
    assert!(timeout(Duration::from_millis(120), socket.recv(&mut [0; 2048])).await.is_err());
}
