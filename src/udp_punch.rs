use hbb_common::{bytes::Bytes, AddrMangle};
use std::{collections::HashMap, net::SocketAddr, time::{Duration, Instant}};

pub(crate) fn enabled(name: &str) -> bool {
    std::env::var(name).map(|v| v == "Y").unwrap_or(false)
}

pub(crate) fn ipv6(bytes: Bytes) -> Bytes {
    if !enabled("ENABLE_IPV6_PUNCH") || bytes.len() != 18 { return Bytes::new(); }
    let addr = AddrMangle::decode(&bytes);
    match addr {
        SocketAddr::V6(v6) if v6.port() != 0 && !v6.ip().is_unspecified()
            && !v6.ip().is_multicast() && !v6.ip().is_unicast_link_local() => bytes,
        _ => Bytes::new(),
    }
}

pub(crate) struct Pending {
    pub peer: SocketAddr,
    pub id: String,
    pub udp: SocketAddr,
    pub created: Instant,
    pub retries: u8,
}

#[derive(Default)]
pub(crate) struct Routes(pub HashMap<SocketAddr, Pending>);

impl Routes {
    pub fn insert(&mut self, route: SocketAddr, pending: Pending) {
        self.0.retain(|_, p| p.created.elapsed() < Duration::from_secs(30));
        if self.0.len() < 4096 { self.0.insert(route, pending); }
    }

    pub fn take(&mut self, route: SocketAddr, source: SocketAddr, id: &str) -> Option<Pending> {
        let pending = self.0.get(&route)?;
        if pending.created.elapsed() >= Duration::from_secs(30) {
            self.0.remove(&route);
            return None;
        }
        if pending.peer.ip() != source.ip() || pending.id != id { return None; }
        self.0.remove(&route)
    }

    pub fn retry(&mut self, source: SocketAddr, id: &str) -> Option<SocketAddr> {
        self.0.iter_mut().find_map(|(route, p)| {
            if p.udp == source && p.id == id && p.retries < 2
                && p.created.elapsed() < Duration::from_secs(30) {
                p.retries += 1;
                Some(*route)
            } else { None }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn replies_require_live_matching_peer_and_are_single_use() {
        let route = "127.0.0.1:1000".parse().unwrap();
        let peer = "127.0.0.2:2000".parse().unwrap();
        let mut routes = Routes::default();
        routes.insert(route, Pending { peer, id: "device".into(), udp: route, created: Instant::now(), retries: 0 });
        assert!(routes.take(route, route, "device").is_none());
        assert!(routes.take(route, peer, "other").is_none());
        assert!(routes.take(route, peer, "device").is_some());
        assert!(routes.take(route, peer, "device").is_none());
        routes.insert(route, Pending { peer, id: "device".into(), udp: route, created: Instant::now() - Duration::from_secs(31), retries: 0 });
        assert!(routes.take(route, peer, "device").is_none());
    }
}
