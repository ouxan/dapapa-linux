#!/bin/sh
# Runs a command inside the Arch Linux development container with the repository mounted at /src.
# Usage: ./dev.sh dotnet build dapapa-linux.slnx
set -e
cd "$(dirname "$0")"
host_dir=$(pwd -W 2>/dev/null || pwd)
docker volume create dapapa-nuget >/dev/null
MSYS_NO_PATHCONV=1 exec docker run --rm --privileged -v "$host_dir:/src" -v dapapa-nuget:/nuget -w /src dapapa-linux-dev "$@"
