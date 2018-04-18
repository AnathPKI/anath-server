#!/usr/bin/env bash
# Build development release
#
# This script has to be called from the source root.

set -ue

echo "$DOCKER_PASSWORD" | docker login -u "$DOCKER_USERNAME" --password-stdin
docker build . -t anath/pki:test
docker push anath/pki:test