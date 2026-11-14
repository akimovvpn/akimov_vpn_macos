# Telegram login for the macOS app

In BotFather → your bot → Login Widget, configure:

| Setting | Value |
| --- | --- |
| Client ID | `9010497295` |
| Trusted Origins | `https://akimov.bid` |
| Redirect URIs | `https://akimov.bid/` |
| Signing algorithm | `RS256` |

The trailing slash on the redirect URI matches the exact URL the app sends. Telegram only accepts pre-registered URLs. The desktop app uses the same `post_message` login flow as Telegram's JavaScript Login library and the existing cabinet website. BotFather's Native Login entries are for the mobile SDK integrations; this macOS flow does not use an iOS/Android registration.

For this app's current popup flow, you do **not** enter the Client Secret anywhere. Telegram returns an ID token, and the cabinet backend verifies its signature with Telegram's public JWKS. The macOS app only uses the public Client ID and a short-lived server challenge.

The Client Secret is needed only if the backend uses Telegram's authorization-code flow and calls `https://oauth.telegram.org/token`. In that case, store it in the backend deployment's secret manager or server-only environment configuration, using the variable name that backend actually reads. This repository contains no backend deployment or secret setting. Do not put the secret in the macOS bundle, frontend, saved preferences, or this repository.

The app asks `POST https://api.akimov.bid/api/v1/auth/telegram/oidc/request` for a short-lived `{token, client_id, nonce, expires_in}` challenge. The public endpoint's client ID was checked against the BotFather screenshot and matched. After Telegram answers, the app submits `{token, id_token}` to `/auth/telegram/oidc/complete`. The challenge token is never sent to Telegram.

The isolated popup only navigates within `https://oauth.telegram.org`. Its local callback is bound to the challenge nonce and intercepted before navigation. The app checks token correlation, issuer, audience, and expiry before submitting it. Those decoded claims are untrusted: the cabinet must still verify the JWT signature using Telegram's JWKS, enforce the configured signing algorithm, validate all claims including nonce, and consume each challenge once. The server must not turn an invalid or replayed token into a session. The backend implementation is outside this repository; its cryptographic verification has not been audited here.

After changing BotFather settings, finish a real Telegram sign-in to validate the deployment. Offline tests check popup isolation, callback correlation, request parameters and rejected token claims; they cannot confirm account consent or server signature verification.

References: [Telegram Login setup and validation](https://core.telegram.org/bots/telegram-login), [official Login library](https://telegram.org/js/telegram-login.js).
