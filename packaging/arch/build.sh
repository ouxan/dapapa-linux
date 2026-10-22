#!/bin/sh
# Builds the Arch package from the current commit. Run as a normal user on Arch (or in the dev container).
set -eu
ROOT=$(cd "$(dirname "$0")/../.." && pwd)
OUT=${1:-"$ROOT/artifacts/package"}
VERSION=$(sed -n 's/^pkgver=//p' "$ROOT/packaging/arch/PKGBUILD")
BUILD=$(mktemp -d)
trap 'rm -rf "$BUILD"' EXIT
git -C "$ROOT" archive --prefix="dapapa-linux-$VERSION/" -o "$BUILD/dapapa-linux-$VERSION.tar.gz" HEAD
cp "$ROOT/packaging/arch/PKGBUILD" "$ROOT/packaging/arch/dapapa.install" "$BUILD/"
mkdir -p "$OUT"
(cd "$BUILD" && PKGDEST="$OUT" makepkg --force --cleanbuild --nodeps)
