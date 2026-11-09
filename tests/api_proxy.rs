mod support;
use hbb_common::{bytes::Bytes, protobuf::Message, rendezvous_proto::*, tokio::{self, io::{AsyncReadExt, AsyncWriteExt}, net::TcpListener, time::{timeout, Duration}}};

#[tokio::test]
async fn encrypted_proxy_preserves_api_auth_status_body_and_actual_source() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let upstream = format!("http://{}", listener.local_addr().unwrap());
    let server = support::Server::start(&[("API_PROXY_UPSTREAM", &upstream)]);
    let response = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.unwrap();
        let mut bytes = Vec::new();
        let mut buffer = [0; 8192];
        while !bytes.ends_with(b"payload") {
            let count = socket.read(&mut buffer).await.unwrap();
            assert!(count > 0); bytes.extend_from_slice(&buffer[..count]);
        }
        let request = String::from_utf8(bytes).unwrap().to_ascii_lowercase();
        assert!(request.starts_with("post /api/login?query=ok http/1.1"));
        assert!(request.contains("authorization: bearer keep-this-token"));
        assert!(request.contains("x-forwarded-for: 127.0.0.1"));
        assert!(!request.contains("203.0.113.9"));
        assert!(!request.contains("x-remove-me"));
        socket.write_all(b"HTTP/1.1 418 I'm a teapot\r\nContent-Length: 8\r\nX-Api-Result: preserved\r\nConnection: close\r\n\r\napi-body").await.unwrap();
    });
    let mut stream = server.secure(1).await;
    let mut message = RendezvousMessage::new();
    message.set_http_proxy_request(HttpProxyRequest {
        method: "POST".into(), path: "/api/login?query=ok".into(), body: Bytes::from_static(b"payload"),
        headers: vec![header("Authorization", "Bearer keep-this-token"), header("X-Forwarded-For", "203.0.113.9"), header("Connection", "x-remove-me"), header("X-Remove-Me", "private")], ..Default::default()
    });
    stream.send(&message).await.unwrap();
    let bytes = timeout(Duration::from_secs(3), stream.next()).await.unwrap().unwrap().unwrap();
    let Some(rendezvous_message::Union::HttpProxyResponse(result)) = RendezvousMessage::parse_from_bytes(&bytes).unwrap().union else { panic!("missing proxy response"); };
    assert_eq!(result.status, 418);
    assert_eq!(result.body.as_ref(), b"api-body");
    assert!(result.error.is_empty());
    assert!(result.headers.iter().any(|h| h.name == "x-api-result" && h.value == "preserved"));
    response.await.unwrap();
}

fn header(name: &str, value: &str) -> HeaderEntry { HeaderEntry { name: name.into(), value: value.into(), ..Default::default() } }

#[tokio::test]
async fn proxy_rejects_plaintext_and_arbitrary_destinations_without_contacting_upstream() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let upstream = format!("http://{}", listener.local_addr().unwrap());
    let server = support::Server::start(&[("API_PROXY_UPSTREAM", &upstream)]);
    for path in ["http://example.com/api/login", "//example.com/api/login", "/api/../admin", "/api/%2e%2e/admin", "/api/%252e%252e/admin", "/admin", "/api/\\admin"] {
        let mut stream = server.secure(1).await;
        let mut message = RendezvousMessage::new();
        message.set_http_proxy_request(HttpProxyRequest { method: "GET".into(), path: path.into(), ..Default::default() });
        stream.send(&message).await.unwrap();
        let bytes = timeout(Duration::from_secs(3), stream.next()).await.unwrap().unwrap().unwrap();
        let Some(rendezvous_message::Union::HttpProxyResponse(result)) = RendezvousMessage::parse_from_bytes(&bytes).unwrap().union else { panic!("missing rejection"); };
        assert_eq!(result.status, 400, "{path}");
    }
    let mut stream = server.connect().await;
    let mut message = RendezvousMessage::new();
    message.set_http_proxy_request(HttpProxyRequest { method: "GET".into(), path: "/api/login".into(), ..Default::default() });
    stream.send(&message).await.unwrap();
    // Consume the initial advertisement, then the refusal/close.
    let _ = stream.next().await;
    let next = timeout(Duration::from_secs(3), stream.next()).await.unwrap();
    assert!(next.is_none() || matches!(next, Some(Ok(ref bytes)) if matches!(RendezvousMessage::parse_from_bytes(bytes).unwrap().union, Some(rendezvous_message::Union::HttpProxyResponse(ref response)) if response.status == 403)));
    assert!(timeout(Duration::from_millis(100), listener.accept()).await.is_err());
}
