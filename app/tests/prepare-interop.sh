#!/bin/bash
set -euo pipefail
workspace="$(cd "$(dirname "$0")/../.." && pwd)"
case "$(uname -m)" in
    arm64) archive=Xray-macos-arm64-v8a.zip; hash=0a05dca3bd311b0bc5a89c7ce56350cab1e829e131e4b2bcd48eb304fac07e9a;;
    x86_64) archive=Xray-macos-64.zip; hash=37c60b63c77ef5edcfb46a0d70349f7d96e0c132e6a356ead4fd20aeeacc5c75;;
    *) echo 'Unsupported macOS architecture.' >&2; exit 1;;
esac
mkdir -p "$workspace/.tools/xray" "$workspace/.tools/interop"
file="$workspace/.tools/$archive"
if [ ! -f "$file" ]; then curl -fL --retry 3 -o "$file" "https://github.com/XTLS/Xray-core/releases/download/v26.10.31/$archive"; fi
printf '%s  %s\n' "$hash" "$file" | shasum -a 256 -c -
unzip -oq "$file" xray -d "$workspace/.tools/xray"
chmod 755 "$workspace/.tools/xray/xray"
openssl req -x509 -newkey rsa:2048 -sha256 -nodes -days 2 -subj '/CN=localhost' -keyout "$workspace/.tools/interop/key.pem" -out "$workspace/.tools/interop/cert.pem" >/dev/null 2>&1
