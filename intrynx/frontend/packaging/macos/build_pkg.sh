#!/usr/bin/env bash
# Build a macOS installer .pkg from a compiled probe binary.
#   ./build_pkg.sh <path-to-binary> <version>
# Run on macOS. Produces an UNSIGNED pkg; sign+notarize separately (see notes at end).
set -euo pipefail

BIN="${1:?path to compiled binary}"
VERSION="${2:-1.0.0}"
HERE="$(cd "$(dirname "$0")" && pwd)"
APP=netagent
PKGID="com.$APP.probe"
export COPYFILE_DISABLE=1          # don't bundle ._ AppleDouble resource forks

root="$(mktemp -d)"
install -d "$root/usr/local/bin" "$root/Library/LaunchDaemons" \
          "$root/Library/Application Support/$APP"
install -m 0755 "$BIN"                                  "$root/usr/local/bin/$APP"
install -m 0644 "$HERE/com.$APP.probe.plist"            "$root/Library/LaunchDaemons/com.$APP.probe.plist"
install -m 0644 "$HERE/$APP.env.example"                "$root/Library/Application Support/$APP/$APP.env.example"

out="${OUT:-$APP-$VERSION-macos-arm64.pkg}"
pkgbuild \
  --root "$root" \
  --identifier "$PKGID" \
  --version "$VERSION" \
  --scripts "$HERE/scripts" \
  --install-location "/" \
  "$out"
rm -rf "$root"
echo "Built $out (unsigned)"
echo "Sign + notarize:"
echo "  productsign --sign 'Developer ID Installer: <Org>' $out ${out%.pkg}-signed.pkg"
echo "  xcrun notarytool submit ${out%.pkg}-signed.pkg --keychain-profile <p> --wait"
echo "  xcrun stapler staple ${out%.pkg}-signed.pkg"
