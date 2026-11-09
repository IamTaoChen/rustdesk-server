#!/bin/sh

for service in hbbr hbbs; do
  [ "$(/command/s6-svstat -o up /run/s6-rc/servicedirs/$service)" = true ] || exit 1
done
if [ -f /app/apimain ]; then
  [ "$(/command/s6-svstat -o up /run/s6-rc/servicedirs/api)" = true ] || exit 1
fi
