mod support;
use hbb_common::{bytes::Bytes, protobuf::Message, rendezvous_proto::*, tcp::FramedStream, tokio};

async fn result(stream: &mut FramedStream, registration: RegisterPk) -> register_pk_response::Result {
    let mut message = RendezvousMessage::new();
    message.set_register_pk(registration);
    stream.send(&message).await.unwrap();
    loop {
        let bytes = stream.next().await.unwrap().unwrap();
        match RendezvousMessage::parse_from_bytes(&bytes).unwrap().union {
            Some(rendezvous_message::Union::RegisterPkResponse(response)) => return response.result.enum_value().unwrap(),
            Some(rendezvous_message::Union::KeyExchange(_)) => {},
            other => panic!("unexpected registration response: {other:?}"),
        }
    }
}

fn rename(id: &str, uuid: u8) -> RegisterPk {
    RegisterPk { old_id: "123456789".into(), id: id.into(), uuid: Bytes::from(vec![uuid; 16]), ..Default::default() }
}

#[tokio::test]
async fn rename_preserves_key_and_online_session_and_rejects_impostors_and_collisions() {
    use register_pk_response::Result::*;
    let server = support::Server::start(&[]);
    let mut owner = server.secure(1).await;
    assert_eq!(result(&mut owner, RegisterPk { id: "123456789".into(), uuid: Bytes::from_static(&[1;16]), pk: Bytes::from_static(&[2;32]), ..Default::default() }).await, OK);
    let mut other = server.secure(1).await;
    assert_eq!(result(&mut other, RegisterPk { id: "occupied".into(), uuid: Bytes::from_static(&[3;16]), pk: Bytes::from_static(&[4;32]), ..Default::default() }).await, OK);
    assert_eq!(result(&mut server.connect().await, rename("new-name", 9)).await, UUID_MISMATCH);
    assert_eq!(result(&mut server.connect().await, rename("occupied", 1)).await, ID_EXISTS);
    assert_eq!(result(&mut server.connect().await, rename("1bad", 1)).await, INVALID_ID_FORMAT);
    // Official clients perform this request without negotiated encryption or a new public key.
    assert_eq!(result(&mut server.connect().await, rename("new-name", 1)).await, OK);
    let mut query = server.secure(1).await;
    let mut message = RendezvousMessage::new();
    message.set_online_request(OnlineRequest { peers: vec!["123456789".into(), "new-name".into()], ..Default::default() });
    query.send(&message).await.unwrap();
    let bytes = query.next().await.unwrap().unwrap();
    let Some(rendezvous_message::Union::OnlineResponse(response)) = RendezvousMessage::parse_from_bytes(&bytes).unwrap().union else { panic!("missing online response"); };
    assert_eq!(response.states.as_ref(), &[0x40]);
    // Re-registration with the preserved UUID/key succeeds under the new name.
    let mut reconnect = server.secure(1).await;
    assert_eq!(result(&mut reconnect, RegisterPk { id: "new-name".into(), uuid: Bytes::from_static(&[1;16]), pk: Bytes::from_static(&[2;32]), ..Default::default() }).await, OK);
}
