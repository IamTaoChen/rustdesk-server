use hbb_common::{rendezvous_proto::{HeaderEntry, HttpProxyRequest, HttpProxyResponse}, tokio::sync::Semaphore, ResultType};
use reqwest::{header::{HeaderMap, HeaderName, HeaderValue}, Client, Method, Url};
use std::{collections::HashSet, net::SocketAddr, time::Duration};

const REQUEST_LIMIT: usize = 32 * 1024;
const RESPONSE_LIMIT: usize = 48 * 1024;

pub(crate) struct ApiProxy { base: Url, client: Client, limit: Semaphore }

pub(crate) fn error(status: i32, reason: &'static str) -> HttpProxyResponse {
    HttpProxyResponse { status, error: reason.into(), ..Default::default() }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hbb_common::tokio::{self, io::AsyncWriteExt, net::TcpListener};

    fn request() -> HttpProxyRequest { HttpProxyRequest { method: "GET".into(), path: "/api/version".into(), ..Default::default() } }

    #[tokio::test]
    async fn unavailable_upstream_is_retryable_without_replaying_requests() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        drop(listener);
        let proxy = ApiProxy::new(&format!("http://{address}"), Duration::from_secs(1)).unwrap();
        let response = proxy.execute(request(), "127.0.0.1:1234".parse().unwrap()).await;
        assert_eq!(response.status, 503);
        assert_eq!(response.error, "upstream_unavailable");
    }

    #[tokio::test]
    async fn upstream_redirects_are_not_followed_and_oversized_bodies_are_bounded() {
        for (reply, expected) in [
            (b"HTTP/1.1 302 Found\r\nLocation: http://127.0.0.1:1/admin\r\nContent-Length: 0\r\n\r\n".as_slice(), 302),
            (b"HTTP/1.1 200 OK\r\nContent-Length: 60000\r\n\r\n".as_slice(), 502),
        ] {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let proxy = ApiProxy::new(&format!("http://{}", listener.local_addr().unwrap()), Duration::from_secs(1)).unwrap();
            let writer = tokio::spawn(async move {
                use hbb_common::tokio::io::AsyncReadExt;
                let (mut socket, _) = listener.accept().await.unwrap();
                socket.read(&mut [0; 8192]).await.unwrap();
                socket.write_all(reply).await.unwrap();
            });
            assert_eq!(proxy.execute(request(), "127.0.0.1:1234".parse().unwrap()).await.status, expected);
            writer.await.unwrap();
        }
    }

    #[tokio::test]
    async fn stalled_bodies_timeout_and_full_concurrency_refuses_without_queueing() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy = ApiProxy::new(&format!("http://{}", listener.local_addr().unwrap()), Duration::from_millis(80)).unwrap();
        let writer = tokio::spawn(async move {
            use hbb_common::tokio::io::AsyncReadExt;
            let (mut socket, _) = listener.accept().await.unwrap();
            socket.read(&mut [0; 8192]).await.unwrap();
            socket.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\na").await.unwrap();
            tokio::time::sleep(Duration::from_millis(200)).await;
        });
        assert_eq!(proxy.execute(request(), "127.0.0.1:1234".parse().unwrap()).await.status, 504);
        writer.await.unwrap();
        let _permits = proxy.limit.acquire_many(32).await.unwrap();
        assert_eq!(proxy.execute(request(), "127.0.0.1:1234".parse().unwrap()).await.status, 503);
    }

    #[test]
    fn configured_upstream_must_be_one_origin() {
        for value in ["file:///etc/passwd", "http://user:secret@localhost", "http://localhost/api/", "http://localhost/?q=1", "http://localhost/#x"] {
            assert!(ApiProxy::new(value, Duration::from_secs(1)).is_err(), "{value}");
        }
    }
}

fn filtered(name: &str, connection: &HashSet<String>) -> bool {
    connection.contains(name) || name.starts_with("x-forwarded-") || matches!(name,
        "host" | "connection" | "keep-alive" | "proxy-authenticate" | "proxy-authorization" |
        "te" | "trailer" | "transfer-encoding" | "upgrade" | "content-length" | "forwarded" | "x-real-ip")
}

impl ApiProxy {
    pub fn from_env() -> ResultType<Option<Self>> {
        match std::env::var("API_PROXY_UPSTREAM") {
            Ok(value) if !value.is_empty() => Ok(Some(Self::new(&value, Duration::from_secs(10))?)),
            _ => Ok(None),
        }
    }

    fn new(upstream: &str, timeout: Duration) -> ResultType<Self> {
        let base = Url::parse(upstream)?;
        if !matches!(base.scheme(), "http" | "https") || base.host_str().is_none() || !base.username().is_empty()
            || base.password().is_some() || base.path() != "/" || base.query().is_some() || base.fragment().is_some() {
            hbb_common::bail!("API_PROXY_UPSTREAM must be an HTTP(S) origin without credentials, path, query or fragment");
        }
        let client = Client::builder().no_proxy().redirect(reqwest::redirect::Policy::none())
            .gzip(false).connect_timeout(Duration::from_secs(3)).timeout(timeout).build()?;
        Ok(Self { base, client, limit: Semaphore::new(32) })
    }

    fn url(&self, path: &str) -> Option<Url> {
        let raw_path = path.split('?').next()?;
        let lower = raw_path.to_ascii_lowercase();
        if path.len() > 8192 || !path.starts_with("/api/") || raw_path.contains("//")
            || path.bytes().any(|b| b.is_ascii_control() || b == b'\\' || b == b'#')
            || ["%2e", "%2f", "%5c", "%25"].iter().any(|s| lower.contains(s))
            || raw_path.split('/').any(|s| s == "." || s == "..") { return None; }
        let url = self.base.join(path).ok()?;
        if url.origin() != self.base.origin() || !url.path().starts_with("/api/") { return None; }
        Some(url)
    }

    pub async fn execute(&self, request: HttpProxyRequest, source: SocketAddr) -> HttpProxyResponse {
        let _permit = match self.limit.try_acquire() { Ok(permit) => permit, Err(_) => return error(503, "proxy_busy") };
        let url = match self.url(&request.path) { Some(url) => url, None => return error(400, "invalid_path") };
        if !matches!(request.method.as_str(), "GET" | "POST" | "PUT" | "PATCH" | "DELETE" | "HEAD" | "OPTIONS") {
            return error(405, "invalid_method");
        }
        let method = match Method::from_bytes(request.method.as_bytes()) { Ok(method) => method, Err(_) => return error(405, "invalid_method") };
        if request.body.len() > REQUEST_LIMIT || request.headers.len() > 64
            || request.headers.iter().map(|h| h.name.len().saturating_add(h.value.len())).sum::<usize>() > 16 * 1024 {
            return error(413, "request_too_large");
        }
        let connection: HashSet<String> = request.headers.iter().filter(|h| h.name.eq_ignore_ascii_case("connection"))
            .flat_map(|h| h.value.split(',').map(|s| s.trim().to_ascii_lowercase())).collect();
        let mut headers = HeaderMap::new();
        for header in request.headers {
            let name = match HeaderName::from_bytes(header.name.as_bytes()) { Ok(name) => name, Err(_) => return error(400, "invalid_header") };
            if filtered(name.as_str(), &connection) { continue; }
            let value = match HeaderValue::from_str(&header.value) { Ok(value) => value, Err(_) => return error(400, "invalid_header") };
            headers.append(name, value);
        }
        let ip = hbb_common::try_into_v4(source).ip().to_string();
        let value = match HeaderValue::from_str(&ip) { Ok(value) => value, Err(_) => return error(400, "invalid_source") };
        headers.insert("x-forwarded-for", value.clone());
        headers.insert("x-real-ip", value);
        let mut response = match self.client.request(method, url).headers(headers).body(request.body.to_vec()).send().await {
            Ok(response) => response,
            Err(err) => return if err.is_timeout() { error(504, "upstream_timeout") }
                else if err.is_connect() { error(503, "upstream_unavailable") }
                else { error(502, "upstream_unavailable") },
        };
        if response.content_length().map(|len| len > RESPONSE_LIMIT as u64).unwrap_or(false) { return error(502, "response_too_large"); }
        let status = response.status().as_u16() as i32;
        let connection: HashSet<String> = response.headers().get_all("connection").iter().filter_map(|v| v.to_str().ok())
            .flat_map(|v| v.split(',').map(|s| s.trim().to_ascii_lowercase())).collect();
        let mut headers = Vec::new();
        let mut header_size = 0;
        for (name, value) in response.headers() {
            if filtered(name.as_str(), &connection) { continue; }
            let value = match value.to_str() { Ok(value) => value, Err(_) => return error(502, "invalid_upstream_header") };
            header_size += name.as_str().len() + value.len();
            if header_size > 8192 || headers.len() >= 64 { return error(502, "response_headers_too_large"); }
            headers.push(HeaderEntry { name: name.as_str().into(), value: value.into(), ..Default::default() });
        }
        let mut body = Vec::new();
        loop {
            match response.chunk().await {
                Ok(Some(chunk)) => {
                    if body.len().saturating_add(chunk.len()) > RESPONSE_LIMIT { return error(502, "response_too_large"); }
                    body.extend_from_slice(&chunk);
                }
                Ok(None) => break,
                Err(err) => return if err.is_timeout() { error(504, "upstream_timeout") } else { error(502, "upstream_read_failed") },
            }
        }
        HttpProxyResponse { status, headers, body: body.into(), ..Default::default() }
    }
}
