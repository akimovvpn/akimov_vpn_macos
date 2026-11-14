#!/bin/bash
set -euo pipefail
cd "$(dirname "$0")"
[ "$(uname -s)" = Darwin ] || { echo 'Build the app on macOS.' >&2; exit 1; }
target="${1:-$(rustc -vV | sed -n 's/^host: //p')}"
case "$target" in aarch64-apple-darwin) arch=arm64;; x86_64-apple-darwin) arch=amd64;; *) echo 'Use aarch64-apple-darwin or x86_64-apple-darwin.' >&2; exit 1;; esac
CORE_ARCH="$arch" python3 - <<'PY'
import hashlib,json,os,pathlib
root=pathlib.Path('src-tauri/core'); manifest=json.loads((root/'manifest.json').read_text())
assert manifest['target']=='darwin-'+os.environ['CORE_ARCH'], 'Rebuild Mihomo for this architecture first.'
for name,key in [('mihomo','binary_sha256'),('geoip.metadb','geoip_sha256'),('GeoSite.dat','geosite_sha256')]:
    assert hashlib.sha256((root/name).read_bytes()).hexdigest()==manifest[key], 'Core resource checksum mismatch: '+name
PY
export APPLE_SIGNING_IDENTITY="${APPLE_SIGNING_IDENTITY:--}"
npx --yes @tauri-apps/cli@2.12.4 build --ci --target "$target" --bundles app -- --locked
version="$(node -p 'require("./src-tauri/tauri.conf.json").version')"
destination="dist/akimov-vpn-$version-macos-$arch"
mkdir -p "$destination"
ditto "src-tauri/target/$target/release/bundle/macos/akimov vpn.app" "$destination/akimov vpn.app"
stage="$(mktemp -d "$PWD/dist/dmg-stage.XXXXXX")"
trap 'rm -rf "$stage"' EXIT
ditto "$destination/akimov vpn.app" "$stage/akimov vpn.app"
ln -s /Applications "$stage/Applications"
hdiutil create -volname 'akimov vpn' -srcfolder "$stage" -format UDZO -ov "$destination/akimov-vpn-$version-macos-$arch.dmg"
(cd "$destination" && shasum -a 256 ./*.dmg > SHA256SUMS.txt)
printf 'Ready: %s/%s\n' "$PWD" "$destination"
