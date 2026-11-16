# macOS Sign-in Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** The macOS app gets the new sign-in from the spec: a centered lockup, tiles for Telegram, Google, Yandex ID and email, browser hand-off with a 4-digit confirmation code, and email codes. There are no passwords and no embedded login window.

**Architecture:**
- **Rust (`cabinet.rs`):** keeps every secret: the hand-off request token and the email consent ticket. The UI only sees the confirmation code and the result.
- **Hand-off:** the app opens the system browser, the UI polls a Tauri command about once a second, and Rust exchanges the poll result for a verified session.
- **Email:** reuses `Cabinet::auth` with new actions.

**Tech Stack:** Tauri 2 (Rust), vanilla JS UI (`app/ui/app.js`, `style.css`), Node UI tests (`app/tests/ui.test.cjs`, `ui-render.cjs`).

**Spec:** `docs/superpowers/specs/2026-11-15-sign-in-redesign-design.md`, sections "Desktop apps" and "Passwordless email".

## Global Constraints

**Server API:**
- `GET /auth/methods` returns `{telegram, google, yandex, email, email_signin}`.
- `POST /auth/oauth/request {provider, client:"desktop"}` returns `{token, state, authorization_url, expires_in:300, confirm_code}`.
- `POST /auth/oauth/poll {token}` returns `{status: pending|confirmed|failed|expired, access_token?, refresh_token?, error?}`.
- `POST /auth/email/code {email}`, then `/auth/email/verify {email, code}`, which returns tokens or `{status:"consent_required", ticket}`.
- `POST /auth/email/create {ticket, accept_terms, accept_personal_data}`.
- Error bodies carry `code`: `code_wait`, `code_invalid`, `code_expired`, `code_locked`, `code_limit`, `signup_closed`, `signup_expired`.

**App behaviour:**
- **Language:** the app stays in English and the brand stays Cyrillic. Server messages are Russian, so Rust maps machine codes to English text.
- **Browser links:** only `https://oauth.telegram.org/auth`, `https://accounts.google.com/o/oauth2/v2/auth` and `https://oauth.yandex.ru/authorize`, with `redirect_uri` exactly `<cabinet_url>/auth/<provider>/callback`.
- **Secrets stay in Rust:** the request token and the consent ticket never reach the UI.
- **Server unreachable:** show the methods last received (all four if none were ever received), plus a "Can't reach the server" note.

## Review Focus

- A poll result arriving after the user cancelled or started another provider must not sign in.
- An authorization URL pointing elsewhere (a different host, `http`, or another provider's callback) must never be opened.
- A new email address must not see consent ticks before its code is verified, and existing accounts must never see them.
- Signing in must replace the previous account's VPN subscription, the same way today's sign-in does.

### Task 1: Rust sign-in calls

**Files:**
- `app/src-tauri/src/cabinet.rs`: replace `TelegramChallenge`, `telegram_*` and `login` with `OAuthRequest`, `oauth_start`, `oauth_poll` and `oauth_cancel`; change the actions in `auth`.
- `app/src-tauri/src/main.rs`: commands `cabinet_methods`, `cabinet_oauth_start`, `cabinet_oauth_poll` and `cabinet_oauth_cancel`; remove `cabinet_login` and `cabinet_telegram_login`.

**Interfaces:**
- `Cabinet::methods() -> Result<Value,String>` (GET with no session).
- `Cabinet::oauth_start(provider) -> Result<(Url, Value),String>`: returns the URL to open and `{confirm_code, expires_in}`.
- `Cabinet::oauth_poll() -> Result<Value,String>`:
  - `{status:"pending"}`;
  - `{status:"signed_in", me}`;
  - `{status:"expired"}`;
  - otherwise an error ("Sign-in was not completed. Try again.").
- `Cabinet::oauth_cancel()`.
- `auth` actions:
  - `email-code {email}` returns `{status:"code_sent"}`;
  - `email-verify {email, code}` returns `{status:"signed_in", me}` or `{status:"consent_required"}`, with the ticket kept in Rust;
  - `email-create {accept_terms, accept_personal_data}` returns `{status:"signed_in", me}`.

**Tests (Rust):**
- `oauth_request_accepts_only_registered_providers_and_callbacks`;
- `oauth_poll_without_a_request_or_after_cancel_never_signs_in`;
- `email_errors_map_machine_codes_to_english`;
- `email_actions_validate_input_and_keep_the_ticket_private`.

### Task 2: The new screen

**Files:** `app/ui/app.js` (`signInScreen` and the auth handlers), `app/ui/style.css`, `app/tests/ui.test.cjs`, `app/tests/ui-render.cjs`.

**Behaviour:**
- **Layout:** a centered lockup (`markSVG` plus the wordmark), with the header logo hidden while signed out. Then tiles for the enabled methods: the last used one is pre-selected (`localStorage` `akimov:last-login`) and marked "Last used". Then the panel.
- **Provider panel:**
  - «Continue with …» runs `cabinet_oauth_start`.
  - The waiting state shows «Enter 4831 in your browser to finish», plus «Cancel» and «Try again».
  - The UI polls `cabinet_oauth_poll` every 1.5 s until signed in, expired or cancelled.
- **Email panel:**
  - Step 1: the address, then «Get code».
  - Step 2: the 6-digit code, «Send a new code» (enabled after 60 s, with a countdown) and «Change email».
  - Step 3 (new address only): the two consent ticks with the legal links, then «Create account».
- **Email switched off but mail works:** the email tile is hidden, and a quiet «Sign in with email» link opens the same flow.

**Tests:**
- No `type="password"` anywhere.
- One tile per enabled method.
- The provider flow shows the code, then a poll signs in.
- Cancel stops polling.
- Email to code to signed in, for an existing account.
- Email to code to consent to create, for a new address.
- The resend countdown.
- Email switched off shows the quiet link.
- Methods endpoint down: the methods last received, plus the note.

### Task 3: Version 1.0.16, build and review

- Bump the version in `Cargo.toml` and `tauri.conf.json` to 1.0.16.
- Run `cargo fmt --check`, `cargo test` and `clippy -D warnings`, plus all `app/tests/*.cjs` the workflow runs.
- Build the arm64 and amd64 DMGs.
- Do a fresh whole-change review, then fix what it finds.
