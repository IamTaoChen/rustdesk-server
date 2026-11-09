# Build and validate with Docker

Initialize the shared protocol submodule, then build from the repository root:

```sh
git submodule update --init --recursive
docker build -f docker/Dockerfile.source -t rustdesk-server:local .
```

The source image uses Rust 1.92, the committed lockfile, Debian 13 and s6-overlay 3.2.3.2. Its default target runs `hbbs` and `hbbr` under s6, with a health check for live services. Set `S6_ARCH=aarch64` for ARM64 or the matching s6 architecture for another platform. The builder runs for the selected Docker platform. `.dockerignore` allows only build inputs: local environment files, credentials, Git history, runtime data and development artifacts are excluded. The tracked SQLite schema fixture is available only to the compiler; it is not copied into the runtime image.

To bundle your API implementation, supply an image containing `/app/apimain`, its configuration and resources:

```sh
docker build -f docker/Dockerfile.source --target with-api \
  --build-arg API_IMAGE=your-registry/rustdesk-api:your-tag \
  -t rustdesk-server:with-api .
```

The default API image is the upstream `lejianwen/rustdesk-api:latest`; override it with your fork and preferably an immutable digest. The API target enables `API_PROXY_UPSTREAM=http://127.0.0.1:21114`. The server-only target leaves proxying disabled unless configured. API authentication and policy remain in that API image. Persist `/data` for server keys/database and `/app/data` for API data. Configure your own relay host and API options rather than exposing the example defaults.

The existing `docker/Dockerfile` and official CI retain the precompiled-binary packaging flow with `docker/` as the context. `Dockerfile.source` is a separate source-build entry point and requires the repository root as context.

## Runtime options

| Variable | Default | Purpose |
| --- | --- | --- |
| `RELAY` | `relay.example.com` | Advertised relay host(s), comma separated |
| `ENCRYPTED_ONLY` | `0` | `1` requires the configured server key, preserving upstream behavior |
| `RMEMS` | `0` | UDP receive buffer option passed to hbbs `-M` |
| `ENABLE_UDP_PUNCH` | unset | `Y` enables experimental correlated UDP punching |
| `ENABLE_IPV6_PUNCH` | unset | `Y` enables IPv6 address metadata |
| `API_PROXY_UPSTREAM` | unset; loopback API in `with-api` | Fixed API origin |
| `SECURITY_LOG_FILE` | unset | Optional separate append-only JSON Lines file; otherwise stderr |

Key negotiation, persistent registration and WebRTC forwarding need no feature switch. WebRTC's transport requirements are in `signaling.md`. Security collection/parser configuration is in `security-logging.md`; create the log directory before setting a file destination. The API proxy's limits and trust setup are in `api-proxy.md`. Relay selection retains upstream round robin; weighted selection is deferred.
