# Security events and CrowdSec

`hbbs` and `hbbr` write security events as one JSON object per line to stderr. Set `SECURITY_LOG_FILE=/data/logs/security.jsonl` to append them to a separate file instead. Create the parent directory and grant the service write access. Rotate this file by restarting the service after rotation (or use copytruncate). A file-open/write failure falls back to stderr; regular diagnostic logs still go to stdout.

Schema version 1 contains `timestamp` (RFC3339 UTC), `service`, `event`, `source_ip`, `source_port`, `transport`, `outcome`, and optional `device_id`. IPv4-mapped IPv6 addresses are normalized. Credentials, UUIDs, public keys and authorization headers are excluded. Events cover rejected registrations, server-key failures, rejected encrypted handshakes and successful device renames. Duplicate-ID and API proxy events use the same schema. An authentication failure here means a server key failed; user-login policy belongs to the API.

The collector, transport, scenarios and enforcement stay on your central CrowdSec host. Copy `contrib/crowdsec/parsers/security-json.yaml` into its `parsers/s01-parse/` directory. Label collected raw JSON lines `type: security-json`, as in the acquisition example. This reusable field mapper accepts any service emitting these standard fields; it does not need a RustDesk-specific grok expression. A Docker JSON envelope must be unwrapped before this mapper sees the inner line. Diagnostic text does not match the parser filter.

Verify on the central host with:

```sh
cscli explain --file /var/log/rustdesk/security.jsonl --type security-json
```

Use `evt.Meta.source_ip`, `evt.Meta.service`, `evt.Meta.log_type` and `evt.Meta.outcome` in your scenarios. No default ban scenario is installed: policy, thresholds and allowlists belong to your central deployment. Duplicate-ID warnings are operational signals and should not automatically trigger bans. WebSocket source addresses retain upstream's trusted-forwarded-header behavior; expose that port only through your trusted TLS proxy, which overwrites those headers.

## Duplicate device IDs

`duplicate_id` / `multiple_live_sources` is emitted when two socket addresses each send at least nine accepted registration/heartbeat observations within five minutes and both remain active within 40 seconds. Counted observations must be at least five seconds apart. This detects sustained clones, including different ports behind one NAT, while suppressing bursts and normal roaming. Each ID warns once per five-minute window. Tracking is bounded to 4096 IDs and four sources per ID, with stale records removed on observation. Detection does not change routing, rename devices, refuse access or ban IPs.
