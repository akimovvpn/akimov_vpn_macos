#!/bin/bash
set -euo pipefail
app_dir="$(cd "$(dirname "$0")" && pwd)"
workspace="$(dirname "$app_dir")"
arch="${1:-$(uname -m)}"
case "$arch" in arm64|aarch64) arch=arm64;; x86_64|amd64) arch=amd64;; *) echo 'Use arm64 or amd64.' >&2; exit 1;; esac
cache="$workspace/.tools"
output="$app_dir/src-tauri/core"
mkdir -p "$cache" "$output"
archive="$cache/mihomo-v1.19.33.zip"
source_hash=bb705aa873fc0e9db352fdc69b992c93fad5b310756e0e5f81194a0e0c108e21
if [ ! -f "$archive" ]; then curl -fL --retry 3 -o "$archive" https://codeload.github.com/MetaCubeX/mihomo/zip/refs/tags/v1.19.33; fi
printf '%s  %s\n' "$source_hash" "$archive" | shasum -a 256 -c -
build="$(mktemp -d "$cache/core-build.XXXXXX")"
trap 'rm -rf "$build"' EXIT
unzip -q "$archive" -d "$build"
cd "$build/mihomo-1.19.33"
git init --quiet
for patch in reality-client url-test-status url-test-keepalive url-test-recovery startup-ready; do
    git apply --check "$app_dir/core-patches/$patch.patch"
    git apply "$app_dir/core-patches/$patch.patch"
done
export GOTOOLCHAIN=go1.26.10
# Regression tests run on the build host; only the final executable is cross-compiled.
go test -buildvcs=false ./component/tls ./adapter/outbound ./adapter ./adapter/outboundgroup -run 'Test(RealityClientVersions|ModernRealityHelloAndLegacyOptOut|URLTestRequiresExpectedStatus|URLTestUnifiedKeepAlive|URLTestRecoversCachedDeadMember)' -count=1
CGO_ENABLED=0 GOOS=darwin GOARCH="$arch" go build -buildvcs=false -tags with_gvisor -trimpath -ldflags '-s -w -X github.com/metacubex/mihomo/constant.Version=v1.19.33-akimov.5' -o "$output/mihomo" .
chmod 755 "$output/mihomo"
# macOS requires an ad hoc signature even for locally built Apple Silicon executables.
if [ "$(uname -s)" = Darwin ]; then codesign --force --sign - "$output/mihomo"; fi
for spec in 'geoip.metadb geoip.metadb' 'GeoSite.dat geosite.dat'; do
    read -r name remote <<< "$spec"
    if [ ! -s "$output/$name" ]; then
        curl -fL --retry 3 -o "$output/$name.tmp" "https://github.com/MetaCubeX/meta-rules-dat/releases/download/latest/$remote"
        [ "$(wc -c < "$output/$name.tmp")" -gt 1048576 ] || { echo 'Incomplete routing database.' >&2; exit 1; }
        mv "$output/$name.tmp" "$output/$name"
    fi
done
CORE_OUTPUT="$output" CORE_ARCH="$arch" CORE_APP="$app_dir" python3 - <<'PY'
import hashlib, json, os, pathlib, subprocess
out = pathlib.Path(os.environ['CORE_OUTPUT']); app = pathlib.Path(os.environ['CORE_APP'])
def sha(path): return hashlib.sha256(path.read_bytes()).hexdigest()
manifest = dict(version='v1.19.33-akimov.5', upstream='https://github.com/MetaCubeX/mihomo/tree/v1.19.33', source_archive_sha256='bb705aa873fc0e9db352fdc69b992c93fad5b310756e0e5f81194a0e0c108e21', target='darwin-'+os.environ['CORE_ARCH'], binary_sha256=sha(out/'mihomo'), geoip_sha256=sha(out/'geoip.metadb'), geosite_sha256=sha(out/'GeoSite.dat'), toolchain=subprocess.check_output(['go','version'],text=True).strip())
for key, name in [('patch_sha256','reality-client'), ('url_test_patch_sha256','url-test-status'), ('url_test_keepalive_patch_sha256','url-test-keepalive'), ('url_test_recovery_patch_sha256','url-test-recovery'), ('startup_ready_patch_sha256','startup-ready')]: manifest[key] = sha(app/'core-patches'/(name+'.patch'))
(out/'manifest.json').write_text(json.dumps(manifest, indent=2)+'\n')
PY
