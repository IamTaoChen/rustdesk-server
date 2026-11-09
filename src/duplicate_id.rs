use std::{collections::HashMap, net::SocketAddr, time::{Duration, Instant}};

struct Source { count: u8, last: Instant }
struct Device {
    sources: HashMap<SocketAddr, Source>,
    window: Instant,
    last: Instant,
    warned: bool,
}

#[derive(Default)]
pub(crate) struct Tracker { devices: HashMap<String, Device> }

impl Tracker {
    pub fn observe(&mut self, id: &str, addr: SocketAddr, now: Instant) -> bool {
        self.devices.retain(|_, device| now.duration_since(device.last) < Duration::from_secs(300));
        if !self.devices.contains_key(id) && self.devices.len() >= 4096 { return false; }
        let device = self.devices.entry(id.to_owned()).or_insert_with(|| Device {
            sources: HashMap::new(), window: now, last: now, warned: false,
        });
        if now.duration_since(device.window) >= Duration::from_secs(300) {
            device.sources.clear(); device.window = now; device.warned = false;
        }
        device.last = now;
        device.sources.retain(|_, source| now.duration_since(source.last) <= Duration::from_secs(40));
        if !device.sources.contains_key(&addr) && device.sources.len() >= 4 { return false; }
        let source = device.sources.entry(hbb_common::try_into_v4(addr)).or_insert(Source { count: 0, last: now });
        if source.count == 0 || now.duration_since(source.last) >= Duration::from_secs(5) {
            source.count = source.count.saturating_add(1).min(9);
            source.last = now;
        }
        if !device.warned && device.sources.values().filter(|s| s.count >= 9).count() >= 2 {
            device.warned = true;
            true
        } else { false }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{Instant, Duration};
    #[test]
    fn two_sustained_sources_warn_once_but_bursts_and_roaming_do_not() {
        let mut tracker = Tracker::default();
        let a = "192.0.2.1:1000".parse().unwrap();
        let b = "192.0.2.1:2000".parse().unwrap();
        let start = Instant::now();
        for _ in 0..50 { assert!(!tracker.observe("burst", a, start)); assert!(!tracker.observe("burst", b, start)); }
        for i in 0..9 {
            let time = start + Duration::from_secs(i * 10);
            assert!(!tracker.observe("cloned", a, time));
            assert_eq!(tracker.observe("cloned", b, time), i == 8);
        }
        assert!(!tracker.observe("cloned", a, start + Duration::from_secs(90)));
        assert!(!tracker.observe("cloned", b, start + Duration::from_secs(90)));
        for i in 0..9 { assert!(!tracker.observe("roaming", a, start + Duration::from_secs(i * 10))); }
        for i in 0..9 { assert!(!tracker.observe("roaming", b, start + Duration::from_secs(130 + i * 10))); }
    }

    #[test]
    fn tracking_is_bounded_and_expired_devices_release_capacity() {
        let mut tracker = Tracker::default();
        let addr = "192.0.2.1:1000".parse().unwrap();
        let now = Instant::now();
        for id in 0..5000 { tracker.observe(&id.to_string(), addr, now); }
        assert!(tracker.devices.len() <= 4096);
        tracker.observe("fresh", addr, now + Duration::from_secs(301));
        assert_eq!(tracker.devices.len(), 1);
    }
}
