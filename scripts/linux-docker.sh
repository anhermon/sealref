#!/bin/bash
# Host side: build the Linux image and run an e2e case on colima's Docker.
# usage: scripts/linux-docker.sh desktop|headless   (repo must be under $HOME)
set -eu
MODE=${1:?desktop|headless}
ROOT=$(cd "$(dirname "$0")/.." && pwd)
CTX=${SEALREF_DOCKER_CONTEXT:-colima}
docker --context "$CTX" build -q -t sealref-linux -f "$ROOT/scripts/Dockerfile.linux" "$ROOT/scripts"
if [ "$MODE" = desktop ]; then
  WRAP='dbus-run-session -- bash /src/scripts/linux-e2e.sh desktop'
else
  WRAP='bash /src/scripts/linux-e2e.sh headless'
fi
docker --context "$CTX" run --rm -v "$ROOT":/src:ro sealref-linux bash -c "$WRAP"
