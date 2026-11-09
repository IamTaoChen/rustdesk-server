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

## Non-root runtime

Both packaging entry points and both source targets run the entire process tree, including s6, as UID/GID `10001:10001`. The image prepares `/run` and `/data` for this identity; the API target also prepares `/app/data` and `/app/runtime`. Programs and configuration stay owned by root. Runtime initialization does not change file ownership or elevate privileges. Do not enable `privileged` or add capabilities.

New Docker named volumes inherit the image directory ownership:

```sh
docker run -d --name rustdesk \
  --cap-drop ALL --security-opt no-new-privileges \
  -e RELAY=relay.example.com \
  -p 21115:21115 -p 21116:21116 -p 21116:21116/udp \
  -p 21117:21117 -p 21118:21118 -p 21119:21119 \
  -v rustdesk-data:/data rustdesk-server:local
```

For existing volumes or bind mounts, stop the old container, back up the data, and give UID/GID `10001:10001` ownership before starting the new image. For example, run `sudo chown -R 10001:10001 ./data` on the host for a `./data:/data` mount. Apply the same migration to mounted API data/log directories. Keep private keys at mode `0600`; do not make directories world-writable. Secrets must be readable by the runtime UID; configure their ownership at deployment. Imported keys are copied into `/data` with restrictive permissions and validated at startup. An unwritable `/data` or inaccessible existing key fails initialization instead of silently continuing. Changing `--user` to an arbitrary UID requires preparing all these writable locations for that identity yourself.

For a read-only root filesystem, add:

```sh
--read-only \
--tmpfs /run:uid=10001,gid=10001,mode=0755,exec \
--tmpfs /tmp:mode=1777
```

The executable `/run` tmpfs is required by s6. Keep the data volumes writable. With the API target, also mount a writable log directory at `/app/runtime`, or add `--tmpfs /app/runtime:uid=10001,gid=10001,mode=0750` for disposable logs. API images with additional write destinations need corresponding writable mounts; custom configurations and resources must be readable by UID `10001`.

Run the Docker smoke checks against your built images:

```sh
python3 docker/tests/nonroot.py rustdesk-server:local
python3 docker/tests/nonroot.py rustdesk-server:local --read-only
python3 docker/tests/nonroot.py rustdesk-server:with-api --api
python3 docker/tests/nonroot.py rustdesk-server:with-api --api --read-only
```

These checks use disposable containers and anonymous data volumes, verify every process's credentials, zero capabilities and forbidden privilege escalation, then check key ownership, identity preservation across restart, service health, clean shutdown and the API version endpoint when enabled.

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
