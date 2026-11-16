#!/bin/bash
# Host side: build the Linux image and run an e2e case on colima's Docker.
# usage: scripts/linux-docker.sh desktop|headless|keyrings-alt   (repo must be under $HOME)
#   keyrings-alt = desktop flow in an image that also has keyrings.alt installed
set -eu
MODE=${1:?desktop|headless|keyrings-alt}
ROOT=$(cd "$(dirname "$0")/.." && pwd)
CTX=${SEALREF_DOCKER_CONTEXT:-colima}
IMAGE=sealref-linux
EXTRA_PIP=""
if [ "$MODE" = keyrings-alt ]; then
  IMAGE=sealref-linux-alt
  EXTRA_PIP="keyrings.alt"
fi
docker --context "$CTX" build -q -t "$IMAGE" --build-arg "EXTRA_PIP=$EXTRA_PIP" \
  -f "$ROOT/scripts/Dockerfile.linux" "$ROOT/scripts"
case "$MODE" in
  desktop|keyrings-alt) WRAP="dbus-run-session -- bash /src/scripts/linux-e2e.sh $MODE" ;;
  headless) WRAP='bash /src/scripts/linux-e2e.sh headless' ;;
  *) echo "usage: $0 desktop|headless|keyrings-alt" >&2; exit 2 ;;
esac
docker --context "$CTX" run --rm -v "$ROOT":/src:ro "$IMAGE" bash -c "$WRAP"
