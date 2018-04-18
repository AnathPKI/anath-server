#!/usr/bin/env bash
# Build development release
#
# This script has to be called from the source root.

set -ue

IMAGE_TAG=anathpki/server:test

echo "$DOCKER_PASSWORD" | docker login -u "$DOCKER_USERNAME" --password-stdin
docker build . -t $IMAGE_TAG
docker push $IMAGE_TAG