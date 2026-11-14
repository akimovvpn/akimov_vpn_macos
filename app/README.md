# akimov vpn · macOS

Ported from akimov_windows commit `a038d16`, preserving its cabinet API and Dust interface: email/Telegram sign-in, registration and password reset, subscriptions and server selection, plans, balance, promo codes, referrals, devices, per-app/domain routing rules, latency tests and live connections.

## Build

Requires macOS 12+, Xcode command line tools, Rust, Node.js 24+ and Go (the script downloads the pinned Go 1.26.10 toolchain automatically). From the repository root:

```sh
./app/build-core.sh                  # native architecture, Windows compatibility patches plus core readiness
./app/build.sh                       # native .app and DMG
# Intel cross-build on Apple Silicon:
./app/build-core.sh amd64
rustup target add x86_64-apple-darwin
./app/build.sh x86_64-apple-darwin
```

Build the core separately for each architecture before building the corresponding app. Artifacts are copied into `app/dist`. The DMG contains the app and an Applications shortcut and is created with the macOS disk-image utility. Install the .app into Applications before first use.

Local builds are ad hoc signed. Distribution requires an Apple Developer ID signature and notarization; configure Tauri's `APPLE_SIGNING_IDENTITY` and Apple notarization credentials in release CI. Updates are installed manually. A signed macOS updater/feed is not included.

## macOS networking

Whole device uses Mihomo's native `utun` adapter with TCP, UDP and DNS. Proxy mode sets HTTP, HTTPS and SOCKS for existing macOS network services; apps must honor the system proxy. The first connection in either mode asks an administrator to install the protected launchd helper. Subsequent connections reuse it. The app and account UI run as the logged-in user. Moving/updating the app can require helper replacement consent.

The helper is installed under `/Library/Application Support/vpn.akimov.macos`, with `/Library/LaunchDaemons/vpn.akimov.helper.plist`. Only the installing user's UID can use its local socket. The controller secret and TUN runtime remain private to root. Provider caches are private, keyed by their source, retain freshness timestamps, and are removed on sign-out. The helper rebuilds incoming YAML, rejects file paths and executable hooks, and permits only the app's fixed controller operations. It runs no core while idle. Connected requires both data-plane readiness after providers load and an active owned TUN interface; a responding controller alone is insufficient. Disconnect, quit, or the app's connection closing stops the owned core and restores network settings. Local probe cores use a pipe supervisor so they also stop if the app crashes. DNS uses public resolvers routed through TUN; previous DNS settings are restored afterward. A root-only recovery record is persisted before network changes and retried after helper restart. Another app's changed proxy or DNS fields are preserved.

Closing the window keeps the VPN running in the menu bar by default. Open the menu to reconnect, disconnect, show the window or quit. Turning off Keep running in the menu bar makes closing disconnect and quit. Cmd-Q always quits. An existing instance is brought forward instead of starting another core.

Controller calls use independent authenticated broker connections so slow probes cannot block UI actions or disconnect. Only one installing macOS user owns the helper. Newly added network services require reconnecting to receive proxy/DNS settings. No kill switch, login autostart, automatic subscription refresh, or live purchase automation is included. Other VPNs can conflict over routes and DNS.

## Privacy and storage

Data lives in `~/Library/Application Support/akimov-vpn`, restricted to the current user. Refresh-token session data lives in the login Keychain, with only a marker in cabinet.json. Access tokens stay in Rust memory. Hardware identification is mandatory: IOPlatformUUID is hashed with an app-specific prefix; the raw UUID is never sent. Subscription files and provider caches contain credentials; do not share the data directory. Sign-out removes the local session and profiles. Dragging the app to Trash does not remove saved data or the helper.

To remove the helper, disconnect and quit first, then run `./uninstall-helper.sh` from this directory. It asks for administrator permission and removes the protected helper and launchd registration; user profiles and Keychain data remain until sign-out/deletion. Removing the helper while connected is refused.

## Checks

```sh
cargo fmt --manifest-path app/src-tauri/Cargo.toml -- --check
cargo test --locked --manifest-path app/src-tauri/Cargo.toml
cargo clippy --locked --manifest-path app/src-tauri/Cargo.toml --all-targets -- -D warnings
node app/tests/ui.test.cjs
node app/tests/macos.test.cjs
node app/tests/telegram-auth.cjs
node app/tests/core-ready.cjs
node app/tests/ui-render.cjs
node app/tests/core-selection.cjs
cargo build --locked --manifest-path app/src-tauri/Cargo.toml
node app/tests/macos-lifecycle.cjs
```

Checks use local fixtures and do not switch the computer's routes or system proxy. The ignored Keychain test writes and removes an isolated test session. No live login, payment, device revocation, privileged TUN connection, or persistent proxy change is performed by ordinary validation. Real TUN TCP/UDP/DNS and network recovery still require an explicit on-device acceptance check.

Mihomo v1.19.33-akimov.5 is the same separate GPL-3.0 core as the Windows app, compiled for Darwin with `with_gvisor`. Source, all four patches, build provenance and routing data hashes are recorded in `src-tauri/core/manifest.json`; see `core-patches/README.md` and bundled licenses. Fonts use SIL OFL; flags use Twemoji CC-BY 4.0. macOS uses its built-in TUN support, without Wintun.

Telegram Login uses client `9010497295`; configure the exact BotFather origin and redirect in [TELEGRAM_LOGIN.md](TELEGRAM_LOGIN.md). No client secret is included in the app.

For a real TUN acceptance check, disconnect akimov, leave Happ connected, then run `node app/tests/macos-live-tun.cjs --live`. It uses the selected saved profile, asserts the system route uses akimov’s own utun interface, transfers HTTPS and UDP DNS, then stops the helper session and checks the original route is restored. Happ's existing routes must remain present throughout. The app splits Mihomo's default Darwin ranges into more specific routes so they can coexist with Happ; removing akimov's interface exposes Happ's original routes again. More specific routes installed by another VPN can still take precedence.

Routing references checked: [FlClash TUN model](https://github.com/chen08209/FlClash/blob/main/lib/models/clash_config.dart), [Koala defaults](https://github.com/coolcoala/koala-clash/blob/main/src/main/utils/template.ts), [Flowvy TUN documentation](https://docs.flowvy.io/dashboard/tun-mode.md), and [Mihomo route-address](https://wiki.metacubex.one/en/config/inbound/tun/#route-address). Flowvy does not publish its desktop implementation. The coexistence route split is our macOS configuration policy, not a claim that these clients implement the same split.

### Administrator authentication

The local ad hoc build uses macOS administrator authorization when installing or replacing its protected network helper. Ordinary connections reuse the helper. On the tested Mac, LocalAuthentication reports Touch ID available, but both the script authorization and Apple's Installer request a password. The app cannot promise fingerprint approval for those dialogs. The package experiment was not integrated; the existing installer and working helper were restored. No PAM, sudo, or authorization-database settings were changed. Apple's SMAppService bundled LaunchDaemon path requires notarization; no Developer ID signing identity is installed locally, and signing alone does not guarantee that macOS offers Touch ID.
