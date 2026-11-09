#!/usr/bin/env python3
"""Smoke-test a built server image; add --api for the bundled API target."""
import argparse
import hashlib
import json
import subprocess
import time
import urllib.error
import urllib.request
import uuid


def docker(*args, check=True):
    result = subprocess.run(["docker", *args], text=True, capture_output=True)
    if check and result.returncode:
        raise RuntimeError(f"docker {args[0]} failed: {result.stderr.strip()}")
    return result


def healthy(name):
    deadline = time.monotonic() + 60
    while time.monotonic() < deadline:
        state = json.loads(docker("inspect", name).stdout)[0]["State"]
        if not state["Running"]:
            raise AssertionError("container exited during startup")
        if docker("exec", name, "/usr/bin/healthcheck.sh", check=False).returncode == 0:
            return
        time.sleep(1)
    raise AssertionError("services did not become healthy")


def verify(image, api, read_only):
    name = "rustdesk-nonroot-" + uuid.uuid4().hex[:12]
    args = ["run", "-d", "--name", name, "--cap-drop", "ALL",
            "--security-opt", "no-new-privileges", "-e", "ENCRYPTED_ONLY=1",
            "-e", "TEST_HBBS=no"]
    if read_only:
        args += ["--read-only", "--tmpfs", "/run:uid=10001,gid=10001,mode=0755,exec",
                 "--tmpfs", "/tmp:mode=1777"]
    if api:
        args += ["-p", "127.0.0.1::21114"]
        if read_only:
            args += ["--tmpfs", "/app/runtime:uid=10001,gid=10001,mode=0750"]
    try:
        docker(*(args + [image]))
        healthy(name)
        # Check every process, including PID 1 and s6, rather than only docker exec.
        docker("exec", name, "sh", "-ec", '''
for status in /proc/[0-9]*/status; do
  [ -r "$status" ] || continue
  awk '
    /^Uid:|^Gid:/ { for (i=2; i<=5; i++) if ($i != 10001) bad=1 }
    /^Cap(Inh|Prm|Eff|Bnd|Amb):/ { if ($2 !~ /^0+$/) bad=1 }
    /^NoNewPrivs:/ { if ($2 != 1) bad=1 }
    END { exit bad }
  ' "$status" || exit 1
done
test ! -w /usr/bin/hbbs
test ! -w /etc/s6-overlay/s6-rc.d/hbbs/run
test ! -u /command/s6-overlay-suexec
test -s /data/db_v2.sqlite3
test -s /data/id_ed25519.pub
test "$(stat -c %a /data/id_ed25519)" = 600
test "$(stat -c %u:%g /data/id_ed25519)" = 10001:10001
''')
        private = docker("exec", name, "cat", "/data/id_ed25519").stdout.encode()
        before = hashlib.sha256(private).digest()
        docker("restart", "-t", "10", name)
        healthy(name)
        after = docker("exec", name, "cat", "/data/id_ed25519").stdout.encode()
        assert hashlib.sha256(after).digest() == before, "restart replaced server identity"
        if api:
            docker("exec", name, "sh", "-ec",
                   "test -w /app/data && test -w /app/runtime && "
                   "test ! -w /app/apimain && test ! -w /app/conf")
            state = json.loads(docker("inspect", name).stdout)[0]
            port = state["NetworkSettings"]["Ports"]["21114/tcp"][0]["HostPort"]
            deadline = time.monotonic() + 30
            while True:
                try:
                    with urllib.request.urlopen(f"http://127.0.0.1:{port}/api/version", timeout=3) as response:
                        assert response.status == 200
                        break
                except (OSError, urllib.error.URLError):
                    if time.monotonic() >= deadline:
                        raise
                    time.sleep(1)
        if api:
            # A live supervisor process is insufficient when HTTP cannot respond.
            service_path = "/run/s6-rc/servicedirs/api"
            docker("exec", name, "/command/s6-svc", "-p", service_path)
            try:
                assert docker("exec", name, "/command/s6-svstat", "-o", "up", service_path).stdout.strip() == "true", "API process exited"
                if docker("exec", name, "/usr/bin/healthcheck.sh", check=False).returncode == 0:
                    raise AssertionError("health check missed unresponsive API")
            finally:
                docker("exec", name, "/command/s6-svc", "-c", service_path)
            healthy(name)
        service = "api" if api else "hbbs"
        docker("exec", name, "/command/s6-svc", "-d", f"/run/s6-rc/servicedirs/{service}")
        for _ in range(50):
            if docker("exec", name, "/usr/bin/healthcheck.sh", check=False).returncode:
                break
            time.sleep(.1)
        else:
            raise AssertionError("health check missed stopped service")
        docker("stop", "-t", "10", name)
        state = json.loads(docker("inspect", name).stdout)[0]["State"]
        assert state["ExitCode"] == 0, "container did not stop cleanly"
        print(f"{image}: non-root process tree, zero capabilities, keys, restart, health and stop passed"
              + (", API HTTP 200" if api else "")
              + (", read-only root" if read_only else ""), flush=True)
    finally:
        # API startup logs may contain credentials, so do not print them here.
        docker("rm", "-f", "-v", name, check=False)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("image")
    parser.add_argument("--api", action="store_true")
    parser.add_argument("--read-only", action="store_true")
    options = parser.parse_args()
    verify(options.image, options.api, options.read_only)
