#!/usr/bin/env bash
set -euo pipefail

IMAGE="${1:-koropwnz/stab-r2d2-plugin}"
VERSION="${2:-0.2.4}"

docker buildx build \
  --platform linux/arm64,linux/amd64 \
  --tag "${IMAGE}:${VERSION}" \
  --push \
  .

echo "OK: ${IMAGE}:${VERSION}"
