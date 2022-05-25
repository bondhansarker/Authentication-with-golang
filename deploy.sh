#!/bin/sh

set -e

if [ -z "$1" ]; then
  echo "Usage: $0 <tag>"
  exit 0
fi

echo "Docker build with tag: $1"
docker build -t asia-southeast1-docker.pkg.dev/strategic-grove-346615/docker/auth:"$1" .
docker push asia-southeast1-docker.pkg.dev/strategic-grove-346615/docker/auth:"$1"