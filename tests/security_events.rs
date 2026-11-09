use hbbs::security_log::{Event, SecurityEvent};
use hbb_common::tokio;
mod support;

#[test]
fn security_event_is_one_json_line_with_crowdsec_fields_and_no_credentials() {
    let event = SecurityEvent::new("hbbs", Event::RegistrationRejected,
        "[::ffff:192.0.2.10]:12345".parse().unwrap(), "tcp", "uuid_mismatch", Some("device\nname"));
    let line = event.line().unwrap();
    assert_eq!(line.iter().filter(|&&byte| byte == b'\n').count(), 1);
    let value: serde_json::Value = serde_json::from_slice(&line).unwrap();
    assert_eq!(value["schema_version"], 1);
    assert_eq!(value["source_ip"], "192.0.2.10");
    assert_eq!(value["source_port"], 12345);
    assert_eq!(value["service"], "hbbs");
    assert_eq!(value["event"], "registration_rejected");
    assert_eq!(value["transport"], "tcp");
    assert_eq!(value["outcome"], "uuid_mismatch");
    chrono::DateTime::parse_from_rfc3339(value["timestamp"].as_str().unwrap()).unwrap();
    for field in ["uuid", "pk", "token", "licence_key", "authorization"] { assert!(value.get(field).is_none()); }
}

#[hbb_common::tokio::test]
async fn rejected_server_key_is_written_to_configured_json_file() {
    use hbb_common::{protobuf::Message, rendezvous_proto::*};
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("events.jsonl");
    let server = support::Server::start(&[("SECURITY_LOG_FILE", path.to_str().unwrap())]);
    let mut stream = server.secure(1).await;
    let mut message = RendezvousMessage::new();
    message.set_punch_hole_request(PunchHoleRequest { id: "123456789".into(), licence_key: "secret-must-not-appear".into(), ..Default::default() });
    stream.send(&message).await.unwrap();
    let bytes = stream.next().await.unwrap().unwrap();
    assert!(matches!(RendezvousMessage::parse_from_bytes(&bytes).unwrap().union, Some(rendezvous_message::Union::PunchHoleResponse(_))));
    let text = std::fs::read_to_string(path).unwrap();
    assert!(!text.contains("secret-must-not-appear"));
    let value: serde_json::Value = serde_json::from_str(&text).unwrap();
    assert_eq!(value["event"], "authentication_failed");
    assert_eq!(value["source_ip"], "127.0.0.1");
    assert_eq!(value["outcome"], "invalid_key");
}
