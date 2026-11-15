# Telegram login for the macOS app

In BotFather → your bot → Login Widget, configure:

| Setting | Value |
| --- | --- |
| Client ID | `9010497295` |
| Trusted Origins | `https://akimov.bid` |
| Redirect URIs | `https://akimov.bid/auth/telegram/callback` |
| Signing algorithm | `RS256` |

Register that exact callback, without a trailing slash. Keep `https://akimov.bid/` registered while older clients still use the previous popup flow. BotFather's Native Login entries are for mobile SDK integrations; this macOS flow needs no iOS/Android registration.

The cabinet backend must have `TELEGRAM_LOGIN_CLIENT_ID=9010497295`, `CABINET_PUBLIC_URL=https://akimov.bid`, and **`TELEGRAM_LOGIN_CLIENT_SECRET`**, set privately in the server's `.env` or secret manager. This is the Client Secret from BotFather. Never put its value in the macOS bundle, website JavaScript, GitHub source, build arguments, saved app preferences, or a chat.

The app asks `POST https://api.akimov.bid/api/v1/auth/telegram/oauth/request` for a short-lived challenge and authorization URL. The backend generates independent state, nonce, private request token and PKCE verifier. The app opens the fixed Telegram authorization endpoint with `response_type=code` and an S256 challenge; the private request token and PKCE verifier are never sent to Telegram's authorization page.

The isolated webview can navigate only within `https://oauth.telegram.org`. It has no app command permissions or injected login script. The exact HTTPS callback is intercepted before loading, and its state, code, origin and parameters are checked. The app sends `{token, state, code}` to `/auth/telegram/oauth/complete`. Only the backend exchanges the code at Telegram's token endpoint, authenticating with the client secret and supplying its stored verifier and redirect URI. It verifies the returned ID token against Telegram's public keys and validates issuer, audience, expiry and nonce before issuing an app session. Each challenge is consumed once.

Deploy the cabinet backend, website and Caddy callback header changes together. The website callback must preserve its same-origin popup opener and send no referrer; the repository's Caddyfile sets callback-only headers for this. The macOS app intercepts this navigation locally.

Offline tests cover code correlation, URL boundaries, replay protection, code exchange and secret exclusion. A real Telegram consent test still requires the deployed secret and registered callback.

Reference: [Telegram Login and OpenID Connect](https://core.telegram.org/bots/telegram-login).
