# Sign-in redesign and Google / Yandex login

Spans three repositories: `akimov_vpn_cabinet_bot` (Go backend + React website, called "cabinet"), `akimov_vpn_macos`, `akimov_vpn_windows`.

## Why

The owner dislikes the current sign-in screens and wants two more ways to sign in, Google and Yandex ID, with an admin switch per method so the login screens can show, for example, only Telegram. The brand on every screen is **акимов vpn** with its logo lockup.

## Goals

- One new sign-in/sign-up design, used by the website and both desktop apps.
- Sign in or create an account with Telegram, Google, Yandex ID or email.
- Website admin switches per method; every login screen shows only enabled methods.
- Setup instructions for the Google and Yandex developer consoles.

## Non-goals

- Linking Google/Yandex to an existing account from the account page (Telegram linking stays as is). Can follow later.
- Translating the desktop apps to Russian. Apps stay English, website stays Russian; the brand name is always Cyrillic.
- Changing the Telegram Mini App / bot authentication. The switches cover login screens only.

## Anti-goals

- Client secrets in the apps or the website bundle.
- A login screen that shows a method the backend will refuse, or hides every method.

## The chosen design (variant D, logo centered)

Mockup: `.tools/auth-variants/index.html` in the macOS repo (served locally; variant "D · Combined", logo "Centered").

```
              [a] акимов vpn            ← logo lockup, mark 46px, wordmark 30px
     Sign in once and the app remembers you.

  ┌Telegram┐ ┌ Google ┐ ┌ Yandex ┐ ┌ Email ┐   ← one tile per enabled method
     Last used                                ← badge on the last method used here

  ┌───────── Continue with Telegram ─────────┐ ← for Telegram/Google/Yandex
        Opens in your browser, then brings you back here.
  while waiting: "Enter 4831 in your browser to finish"  ← desktop apps only

  or, with Email selected:
  [ Sign in | Create account ]                ← segmented switch
  Email / Password (+ two consent boxes on Create account) / primary button
```

- Single centred column, 400px wide, on the app's design-1 tokens (near-black, peach accent `#FFC7A6`, Geologica).
- One method enabled → no tiles; just that method's button (or the email form).
- Email switched off → no Email tile and no "Create account"; a small "Sign in with email" link under the button/tiles opens the sign-in-only email form for existing users.
- Verify-code, forgot-password and reset steps keep their current content and flow, restyled into the same column under the lockup.
- "Last used" is remembered locally per device.
- Website: same layout at phone and desktop widths; Russian copy stays editable through the existing login-content editor.

## Approaches considered

1. **Browser hand-off with polling (chosen).** The app asks the backend for a sign-in request, opens the system browser at the provider, the provider returns to the cabinet's callback page, which completes the code exchange on the server; the app polls with its private request token until the session is ready. Same for all three providers, no listener in the app, works on macOS and Windows alike. Google forbids sign-in inside embedded webviews, so a browser hand-off is required for Google anyway.
2. Loopback redirect: the app runs a temporary `127.0.0.1` listener and the callback page redirects to it. Faster return, but more moving parts per platform (port, firewall prompts on Windows).
3. Keep embedded login windows (today's Telegram desktop flow). Rejected: Google blocks it.

## Backend (cabinet)

- **Providers.** Generalise the existing Telegram OAuth challenge (`internal/accounts/telegram_oauth.go`, `internal/telegramlogin`) into provider requests for `telegram`, `google`, `yandex`: server-held state, nonce and PKCE verifier; callback `https://<cabinet host>/auth/<provider>/callback`.
  - Google: OpenID Connect, code exchange at Google's token endpoint. The `id_token` comes straight from that endpoint over TLS with the client secret, so per Google's guide its claims are checked (issuer, audience, nonce, expiry) without re-verifying the signature; identity = `sub`. The email counts only on gmail.com/googlemail.com or a Workspace domain (`hd`).
  - Yandex ID: OAuth code exchange, then the user-info endpoint; identity = Yandex user `id`. `default_email` counts only on Yandex's own mail domains.
- **Identities.** Follow the `telegram_id` pattern: nullable unique columns `google_sub` and `yandex_id` on `users`, added through the schema metadata + generated model (do not hand-edit generated files).
- **Account matching.** Existing provider identity → that account. Otherwise, only while email confirmation (SMTP) is on, an email the provider owns that matches an existing account → link and sign in; Gmail spelling variants (dots, +tags, googlemail.com) count as the same mailbox, and several matches are refused. Otherwise create an account, with the same consent handling new Telegram accounts get today. Account merges keep the Google/Yandex links.
- **Desktop hand-off.** A desktop request returns a 4-digit confirmation code that the app shows. The callback page asks the person to type it, then posts `state` + `code` + that code; three wrong codes end the sign-in. This stops someone who was sent a sign-in link by an attacker from signing the attacker's app in. The server finishes the exchange and keeps the result for one retrieval by the holder of the request token; a failed sign-in tells the app why. Requests expire as Telegram challenges do today; results are single-use. Polling has its own rate limit.
- **Switches.** Setting `login_methods` (`telegram`, `google`, `yandex`, `email`; each on/off), edited next to the login content (`content:edit` permission). Public read returns only methods that are on **and** configured (secrets present). At least one must stay on; saving all-off is refused. A disabled Telegram/Google/Yandex is also refused by its endpoints, not just hidden.
- **Email switched off (owner's decision):** new email registration is refused, but email sign-in, verification of an already-started sign-up, and password reset keep working, so existing email-only users are never locked out.
- **Config.** `GOOGLE_LOGIN_CLIENT_ID/SECRET`, `YANDEX_LOGIN_CLIENT_ID/SECRET`, beside `TELEGRAM_LOGIN_CLIENT_*`. Secrets stay out of JSON output.

## Website (cabinet)

- Rebuild `AuthScreen.tsx` to the chosen design; methods come from the public `login_methods` read.
- Admin "Login" section gains the four switches, with "not configured" shown for providers without secrets.
- Web sign-in keeps its popup pattern for all providers; the callback route handles both web popups and desktop hand-offs.

## Desktop apps (macOS, then Windows)

- Replace `signInScreen()` in `app/ui/app.js` and its styles; read enabled methods from the backend at boot. If the backend cannot be reached, show the methods last received (all four if none were ever received) with a "can't reach the server" note, since no method works offline anyway (designer's call).
- Rust `cabinet.rs`: one provider-generic request/poll pair replacing the embedded Telegram window; open the browser with the existing HTTPS-only `open_external` rules; cancel polling when the window closes or the user cancels.
- Windows (`akimov_vpn_windows`) receives the same UI and Rust changes; its code is the origin of the macOS port, so the diff should carry over closely.

## Owner setup (Google / Yandex consoles)

- Google Cloud Console → OAuth consent screen (External; `openid email profile`; logo, privacy and terms links) → Credentials → OAuth client ID → Web application → redirect `https://akimov.bid/auth/google/callback`.
- Yandex OAuth (`oauth.yandex.ru/client/new`) → Web services → redirect `https://akimov.bid/auth/yandex/callback` → permissions: email address, username/avatar.
- Put the IDs/secrets in the backend's private environment; never in chat or the repos.

## Order of work

1. Backend: providers, identities, hand-off, switches, tests with fake providers.
2. Website: new auth screen + admin switches.
3. macOS app, then Windows app.
Live Google/Yandex sign-in can only be verified after the owner creates the console apps.

## Left to the builder

Endpoint names and payloads, callback-page states, poll interval and timeout, exact copy, error messages, test structure.

## Passwordless email (added 2026-11-16)

The owner wants no passwords anywhere: email sign-in is a code sent to the address.

- **Flow, same for existing and new accounts:** enter email → «Получить код» → 6-digit code by email (valid 10 minutes, 5 attempts, a new code at most once a minute) → enter it → signed in. A new address then shows the two consent ticks (offer/terms, personal data — separate, as now) and «Создать аккаунт»; existing accounts never see them.
- **No account enumeration:** requesting a code answers the same whether or not the address has an account.
- **Email needs mail:** the email method counts as configured only when the server can send mail (SMTP). Email switched off still means no new email accounts; existing ones sign in with a code.
- **Passwords leave every screen:** website sign-in, registration, «Забыли пароль», reset links (open the sign-in screen), the account page's «добавить почту» (code only), and later the desktop apps.
- **Owner's decision:** the server keeps accepting the old password sign-in, registration and code-verification endpoints, hidden from every screen, until released desktop apps are updated; then they are removed.
- **Language:** messages from the new sign-in code on the server are Russian like the rest; screens that must react to a specific failure read a machine code (`code`) instead of matching text.
