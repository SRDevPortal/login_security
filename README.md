# Login Security

Channel-independent staff login verification for Frappe v15. Initial delivery is
WhatsApp through Interakt. SMS is a future adapter, not an implemented feature.

## Current behavior

- Password validation precedes a browser-bound, six-digit challenge.
- Redis stores an HMAC digest, never the password or plaintext code.
- Atomic verification prevents replay and concurrent consumption. Resend replaces
  the code without resetting attempts or the ten-minute transaction lifetime.
- A server-side `on_login` guard rejects covered native/API/alternate logins unless
  the custom flow has produced internal proof. Unsupported SSO/reset auto-login
  attempts are rejected; they must return to the shared login flow.
- Existing Frappe account restrictions remain enforced. Overlapping native 2FA is
  refused explicitly; this version does not migrate or disable native 2FA.
- Administrator-assisted enrollment verifies phone possession and provides ten
  single-use recovery codes, displayed once. No unverified self-enrollment.
- Codes are delivered by the dedicated private `wa_chat_hub.authentication` adapter,
  without chat creation, AI processing or payload logging.
- `Administrator` deliberately retains native login as the emergency account.
  Restrict and audit its use before activation. Website users and machine tokens
  are outside staff verification policy.

`sriaas_role_permissions` is not modified or required by this app.

## Install locally / on staging

From a bench with `frappe` and the matching `wa_chat_hub` code installed:

```sh
./env/bin/pip install -e apps/login_security --no-deps
# Register login_security in sites/apps.txt once if not already registered.
bench --site <site> clear-cache
bench --site <site> install-app login_security
bench build --app login_security
bench --site <site> clear-cache
```

Installation always leaves **Activate Login Security for this Site off**. It does not change
native authentication settings or configure a business sender. No live messages
are sent until an administrator explicitly starts enrollment or a configured user
starts a covered login.

## Configure and enroll

1. Open **Login Security Settings** as System Manager.
2. Select the active Interakt Channel Account, approved Authentication template,
   language and approval confirmation. Confirm real account capabilities with the
   provider. The code only uses Interakt's official HTTPS message endpoint.
3. Save with enforcement disabled.
4. Open the staff **User**. Save their **Mobile No.** in international format
   (for example, `+14155552671`). Use **Login Security > Verify Mobile No.**,
   enter your administrator password, then the code received by the staff member.
   The server reads this User's saved number; the verification form cannot override it.
5. Give the displayed recovery codes privately to that staff member. Re-enrollment
   changes the account version and invalidates previous recovery codes/challenges.
6. Check **Enable Login Verification** on each verified pilot User and save.
   Mobile No. becomes mandatory while checked. Server validation rejects blank
   or whitespace-only numbers on every save, including API/import saves.
   Only Administrator/System Manager can change this field. Role membership does
   not select users. With the site service off, the User status shows that the
   account is prepared but verification is inactive.
7. Exercise successful login, direct native/API login denial, recovery, provider
   outage handling and all enabled alternate login routes on staging.
8. Resolve any existing native 2FA policy; the settings controller refuses
   activation while native 2FA is enabled. Never disable an existing security
   requirement without an explicit migration decision.
9. Establish restricted Administrator emergency access and a session-revocation
   procedure. Existing sessions are not automatically verified or revoked by this
   app. Revoke covered sessions during the controlled activation window.
10. Acknowledge the activation checks, save with enforcement enabled, then pilot.

HTTPS is required. Local HTTP is accepted only when developer mode is on and the
request host is localhost, 127.0.0.1 or site1.local. API calls require same-origin
Origin/Referer and an `X-Login-Security: 1` header in addition to normal Frappe CSRF
handling. The browser UI supplies these automatically.

For a local HTTPS tunnel, Login Security also accepts TLS termination by a
loopback proxy when the request host exactly matches the site's configured HTTPS
`host_name` and the forwarded protocol is `https`. A supplied forwarded host must
also match. It does not trust forwarded headers from arbitrary network peers.
Both login and enrollment binding cookies remain Secure on this path. Browser
Origin/Referer must still match the public site; cross-origin requests are rejected.

If enforcement is disabled or a user is outside coverage, the browser delegates
to the native login handler, preserving existing native 2FA/reset behavior.

## Recovery and number changes

After password validation choose **Use a recovery code**. Each code works once.
Recovery remains available when the provider times out or rejects delivery. Sender
misconfiguration may prevent challenge creation; use the restricted administrator
procedure to repair configuration or re-enroll the user. There is no automatic
password-only fallback.

Number changes use **User > Login Security > Change Verified Number**. An operator
confirms their own password and enters the replacement number. The old saved and
verified number remain authoritative until the replacement code is accepted.
Successful completion saves User Mobile No. and enrollment together, replaces
recovery codes and invalidates pending login challenges. Ordinary User saves,
REST updates and imports cannot directly change an enrolled number. A failed or
expired replacement leaves the existing number intact.

Missing, revoked or mismatched enrollment blocks a selected user's login; it does
not silently switch off their checkbox or fall back to password-only access.
Enrollment records cannot be edited through the ordinary document API. An internal
write capability is required. The authenticated, password-confirmed
`login_security.enrollment.revoke` POST method disables enrollment and recovery
codes; covered users then require administrator-assisted re-enrollment.

## User customization and upgrades

All customization belongs to `login_security`: install/migrate hooks create four
database Custom Field records on User, `doctype_js` supplies form actions, and
`doc_events` enforces server-side validation. Core User JSON/Python is unchanged.
The checkbox uses permission level 1 plus an explicit operator check. Verified
number evidence remains in the app's protected Enrollment DocType.

For an existing installation, run `bench --site <site> migrate`, then
`bench build --app login_security` and clear the site cache. The local revision was
synced using `bench --site site1.local execute login_security.install.sync_revision`,
which syncs this app only. Restart managed Python web/workers after deployment so
they load the new code; reload Desk in the browser.

Legacy user/role/all-staff selectors are retained as hidden, read-only history.
Empty coverage migrates automatically. Nonempty coverage remains enforced under
the legacy rules until **Review Coverage Migration** in Settings is reviewed and
applied with an operator password. Reconcile every selected User's saved Mobile
No. first, including disabled accounts. Migration checks an unchanged review,
sets the selected User flags and commits the new policy version atomically.
Repeated migration preserves existing checkbox choices. Migration never activates
the site service. Future SMS delivery can reuse the same User checkbox and policy.

## Security boundaries and operations

Treat all enabled session creation routes as staging acceptance tests. The guard
covers normal `LoginManager.post_login()` routes; custom code that writes sessions
directly must be reviewed separately. Machine tokens/API keys do not use this flow.

Redis loss, connection failure and invalid configuration fail closed for covered
logins. Provider acceptance is not delivery. Delivery callbacks cannot authenticate
anyone. This release does not consume provider webhooks or implement automatic
provider retries. Use the explicit resend action for bounded retries.

Audit events contain user, event/outcome and opaque challenge reference only.
Default retention is 30 days. Transport exceptions and raw provider responses are
not logged. Protect upstream proxy/APM request-body capture separately; application
redaction does not control third-party logging. Redis challenges expire within ten
minutes. The site's existing encryption key derives site/purpose-specific HMACs;
rotating it invalidates challenges and recovery digests.

Rollback is an explicit operational decision: use restricted administrator access,
restore the previously approved login policy, disable the new enforcement if
appropriate, clear pending challenges and assess affected sessions. Do not remove
enrollment/audit data as a routine rollback step.

## Tests

The standalone suite uses an isolated disposable Redis server over a private Unix
socket; it does not flush the bench Redis instance or contact WhatsApp.

```sh
./env/bin/python -m unittest discover -s apps/login_security/login_security/tests -v
```

Site integration tests and the exact verification results are documented in
`IMPLEMENTATION_STATUS.md` as they are completed.

```sh
# Development/staging site only; creates and removes a temporary test user.
# Provider calls are mocked and persisted enforcement remains disabled.
LOGIN_SECURITY_TEST_SITE=<site> ./env/bin/python -m unittest discover -s apps/login_security/login_security/tests -v

# Optional browser tests: install Playwright outside the app runtime dependencies.
NODE_PATH=<directory-containing-playwright> node apps/login_security/login_security/tests/browser_login.cjs
```

Browser tests accept `LOGIN_SECURITY_BROWSER` to use an existing Chrome executable.
They exercise the real frontend script with mocked API responses. Site integration
tests separately exercise real Frappe requests and confirm the login page includes
the custom asset; a live-provider browser journey remains a pilot acceptance check.

## Provider extension

Add an explicit adapter behind `login_security.providers` with `validate_provider`
and `send` behavior returning only accepted/rejected/unknown plus an optional
opaque provider message ID. Extend the settings choices and coverage tests. Keep
challenge generation, rate limits, enrollment, verification and session proof
unchanged. Do not permit clients to choose a weaker delivery channel at login.

Reference: [Interakt Authentication templates](https://www.interakt.shop/resource-center/send-whatsapp-authentication-template/).
# login_security
# login_security
# login_security
