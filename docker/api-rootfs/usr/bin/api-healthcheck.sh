#!/bin/sh

base=${API_HEALTHCHECK_BASE:-http://127.0.0.1:21114}
url=${API_HEALTHCHECK_URL:-${base%/}/api/health}
status=$(curl --noproxy '*' --connect-timeout 1 --max-time 2 -sS -o /dev/null -w '%{http_code}' "$url") || exit 1
[ "$status" = 200 ] && exit 0
# Preserve older supplied API images; never mask a new endpoint's DB failure.
if [ "$status" = 404 ] && [ -z "${API_HEALTHCHECK_URL:-}" ]; then
  status=$(curl --noproxy '*' --connect-timeout 1 --max-time 2 -sS -o /dev/null -w '%{http_code}' "${base%/}/api/version") || exit 1
  [ "$status" = 200 ] && exit 0
fi
exit 1
