# akimov vpn for macOS

Port the adjacent akimov_windows app without changing its cabinet API, user interface, or patched Mihomo version (v1.19.33-akimov.4). Keep authentication, subscriptions, plans, wallet, rules, latency, connections, and close-to-tray behavior.

Reuse Tauri 2 and the existing static frontend. A native rewrite would duplicate tested account and routing logic. Replace Windows APIs with macOS hardware UUID hashing, Keychain session storage, SystemConfiguration proxy settings, and a root-owned launchd helper for whole-device mode. The app stays unprivileged. Only sanitized YAML and a fixed controller operation allowlist cross authenticated local IPC. The helper owns its runtime and kills the core when the owning connection closes. Local probe cores have a parent-death supervisor.

Support macOS 12+, Apple Silicon and Intel through architecture-specific builds. Bundle native Mihomo, routing data, patches, licenses, and reproducible build instructions in the .app; package a DMG. Do not use the Windows update feed. Release signing and notarization require the distributor's Apple credentials; local artifacts are ad hoc signed.

Validation must avoid changing this computer's routes or network proxy. Exercise portable regressions, macOS parsing/IPC/lifecycle tests, real-core traffic/failover, UI fixtures, formatting, lint, and a native release bundle. Privileged live TUN tests remain explicit opt-in.
