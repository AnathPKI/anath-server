#!/usr/bin/env bash
#
# Releases are supposed being built from tag pushes. The last release built will be tagged :latest, beside having the
# version as tag.
#
# The version is pulled from $TRAVIS_BRANCH and supposed to start with `v`, e.g. `v1.0.0`. No check is in place to make
# sure the tag matches the version specified in the pom.xml.
#
# Further, semantic versioning is assumed.

set -eu

IMAGE_TAG_BASE=anathpki/server
IMAGE_LATEST_TAG="${IMAGE_TAG_BASE}:latest"


if ! echo "${TRAVIS_BRANCH}" | grep "^v[0-9]+\.[0-9]+\.[0-9]+\$" >/dev/null 2>&1
then
    echo 'Tag does not match "^v[0-9]+.[0-9]+.[0-9]+$". Assuming non-release tag and do nothing.'
    # Don't make the job fail. Maybe it's a legit non-release tag
    exit 0
fi

SEMANTIC_VERSION=${TRAVIS_BRANCH#v}

echo "$DOCKER_PASSWORD" | docker login -u "$DOCKER_USERNAME" --password-stdin
IMAGE_TAG="${IMAGE_TAG}:${SEMANTIC_VERSION}"

echo "## Building image $IMAGE_TAG"
docker build . -t "${IMAGE_TAG}"
echo "## Pushing image $IMAGE_TAG"
docker push "${IMAGE_TAG}"

echo "## Tagging latest"
docker tag "${IMAGE_TAG}" "${IMAGE_LATEST_TAG}"
echo "## Pushing latest"
docker push "${IMAGE_LATEST_TAG}"
echo "## All done. Happy meal!"