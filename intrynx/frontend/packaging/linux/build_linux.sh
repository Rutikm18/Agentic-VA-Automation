#!/usr/bin/env bash
# Build .deb + .rpm from a compiled probe binary, using fpm.
#   ./build_linux.sh <path-to-binary> <version> <arch>   # arch: amd64|arm64
# Requires: fpm (gem install fpm), and run on Linux.
set -euo pipefail

BIN="${1:?path to compiled binary}"
VERSION="${2:-1.0.0}"
ARCH="${3:-amd64}"
HERE="$(cd "$(dirname "$0")" && pwd)"
APP=netagent

stage="$(mktemp -d)"
install -D -m 0755 "$BIN"                       "$stage/usr/local/bin/$APP"
install -D -m 0644 "$HERE/$APP.service"         "$stage/lib/systemd/system/$APP.service"
install -D -m 0644 "$HERE/$APP.env.example"     "$stage/usr/share/$APP/$APP.env.example"

common=(
  -s dir -C "$stage"
  --name "$APP" --version "$VERSION" --architecture "$ARCH"
  --description "netagent network service"
  --after-install "$HERE/postinstall.sh"
  --before-remove "$HERE/prerm.sh"
  --depends ca-certificates
)

fpm "${common[@]}" -t deb -p "$APP-$VERSION-$ARCH.deb" .
fpm "${common[@]}" -t rpm -p "$APP-$VERSION-$ARCH.rpm" .
rm -rf "$stage"
echo "Built $APP-$VERSION-$ARCH.deb and .rpm"
echo "Sign: dpkg-sig / rpmsign, or serve from a GPG-signed apt/yum repo."
