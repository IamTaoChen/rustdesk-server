use serde::Serialize;
use std::{fs::{File, OpenOptions}, io::{self, Write}, net::SocketAddr, sync::Mutex};
use once_cell::sync::Lazy;

#[derive(Clone, Copy, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Event {
    AuthenticationFailed,
    RegistrationRejected,
    DeviceIdChanged,
    HandshakeRejected,
    DuplicateId,
    ProxyRejected,
    ProxyFailed,
}

#[derive(Serialize)]
pub struct SecurityEvent<'a> {
    schema_version: u8,
    timestamp: String,
    service: &'static str,
    event: Event,
    source_ip: String,
    source_port: u16,
    transport: &'static str,
    outcome: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    device_id: Option<&'a str>,
}

impl<'a> SecurityEvent<'a> {
    pub fn new(service: &'static str, event: Event, addr: SocketAddr, transport: &'static str,
        outcome: &'static str, device_id: Option<&'a str>) -> Self {
        let addr = hbb_common::try_into_v4(addr);
        Self { schema_version: 1, timestamp: chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
            service, event, source_ip: addr.ip().to_string(), source_port: addr.port(), transport, outcome, device_id }
    }

    pub fn line(&self) -> serde_json::Result<Vec<u8>> {
        let mut line = serde_json::to_vec(self)?;
        line.push(b'\n');
        Ok(line)
    }
}

static FILE: Lazy<Mutex<Option<File>>> = Lazy::new(|| {
    let file = std::env::var_os("SECURITY_LOG_FILE").and_then(|path| {
        match OpenOptions::new().create(true).append(true).open(path) {
            Ok(file) => Some(file),
            Err(error) => { eprintln!("Cannot open SECURITY_LOG_FILE, using stderr: {error}"); None }
        }
    });
    Mutex::new(file)
});

pub fn record(service: &'static str, event: Event, addr: SocketAddr, transport: &'static str,
    outcome: &'static str, device_id: Option<&str>) {
    let Ok(line) = SecurityEvent::new(service, event, addr, transport, outcome, device_id).line() else { return; };
    if let Ok(mut file) = FILE.lock() {
        if let Some(file) = file.as_mut() {
            if file.write_all(&line).is_ok() { return; }
        }
    }
    let _ = io::stderr().lock().write_all(&line);
}

pub(crate) fn registration(result: hbb_common::rendezvous_proto::register_pk_response::Result,
    addr: SocketAddr, transport: &'static str, id: &str, rename: bool) {
    use hbb_common::rendezvous_proto::register_pk_response::Result::*;
    let outcome = match result {
        OK if rename => "success",
        OK => return,
        UUID_MISMATCH => "uuid_mismatch",
        TOO_FREQUENT => "rate_limited",
        ID_EXISTS => "id_exists",
        INVALID_ID_FORMAT => "invalid_id_format",
        NOT_SUPPORT => "not_supported",
        _ => "server_error",
    };
    record("hbbs", if result == OK { Event::DeviceIdChanged } else { Event::RegistrationRejected },
        addr, transport, outcome, Some(id));
}
