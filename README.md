# akimov vpn for macOS

The macOS counterpart of `akimov_windows`, with the same cabinet interface and **Mihomo v1.19.33-akimov.5** core, including the Windows compatibility and latency patches plus explicit startup readiness.

Supports macOS 12+ on Apple Silicon and Intel. Includes whole-device TUN, system proxy mode, menu-bar controls, subscriptions, routing rules, latency tests, live connections and account management. First connection installs a protected network helper with administrator consent. Sessions use macOS Keychain and device identity uses a hashed hardware UUID.

```sh
./app/build-core.sh
./app/build.sh
```

The .app and DMG are written to `app/dist`. See [build, security, testing and removal details](app/README.md).

Local builds are ad hoc signed; public distribution requires Developer ID signing and notarization. In-app updates need a macOS release feed. Live privileged networking is separate from the ordinary test suite.
