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

## A?Z configuration guide

This guide configures the existing app; it does not enable any account automatically.
Run shell commands inside Ubuntu/WSL from `/home/srdev/frappe-bench-v15`.
The local site is `sriaas.local`. For another installation, replace that site name
and the public URL in every command. Local changes do not deploy production.

### 1. Confirm prerequisites and choose a pilot

1. Use Frappe v15 with `wa_chat_hub` and `login_security` available in `apps/`.
2. Keep Redis, the web server, and normal bench services running.
3. Have an active Interakt account, its API key, and an approved WhatsApp
   **Authentication** template. A normal marketing/utility template is not a substitute.
4. Choose one enabled **System User** with a working password and access to WhatsApp
   on their own mobile. Do not use `Administrator` as the verification pilot.
5. Keep restricted Administrator emergency access available. That account is
   deliberately exempt from both this app and Frappe's native 2FA.
6. Confirm the site already has an encryption key. Do not replace an existing key:
   it also protects stored credentials and derives challenge/recovery digests.

```sh
cd /home/srdev/frappe-bench-v15
bench --site sriaas.local list-apps
```

### 2. Install once, or update the existing installation

If `login_security` is already installed, use the update commands below and skip
installation. Do not reinstall it to repair settings.

For a first installation with both app source directories already present:

```sh
./env/bin/pip install -e apps/login_security --no-deps
# Ensure sites/apps.txt contains login_security once; do not duplicate it.
# Install wa_chat_hub first if it is not already installed on this site.
bench --site sriaas.local install-app wa_chat_hub
bench --site sriaas.local install-app login_security
bench build --app login_security
bench --site sriaas.local clear-cache
```

Run the `wa_chat_hub` installation command only if that dependency is absent.
First installation leaves site activation OFF.

For an existing installation:

```sh
bench --site sriaas.local migrate
bench build --app login_security
bench --site sriaas.local clear-cache
```

If deliberately syncing only this app instead of a full bench migration:

```sh
bench --site sriaas.local execute login_security.install.sync_revision
bench build --app login_security
bench --site sriaas.local clear-cache
```

Restart the managed web/workers after an update. For a development `bench start`
session, Python's reloader normally reloads code; restart that session if needed.
For a production bench managed by its configured process manager, use the normal
bench restart procedure. Reload Desk after metadata/assets change.

### 3. Configure the public HTTPS address

Login Security supports an app-level **Public Login URL**. This setting takes
precedence over `site_config.host_name` for its trusted HTTPS proxy origin and
leaves the site's configuration file unchanged.

1. Open Login Security Settings at the public HTTPS address as Administrator or
   System Manager.
2. Click **Detect Current Address**. The button reads this browser's HTTPS origin;
   it does not learn or save addresses from anonymous login requests.
3. Review the proposed address and confirm to fill **Public Login URL**.
4. Click **Save** to apply it. Detection alone does not save or activate anything.
5. Open a fresh login at that address and test the pilot.

For this tunnel the field value is `https://dollop-convent-idly.ngrok-free.dev`.
You may also enter a trusted HTTPS origin manually. Paths such as `/login`, query
strings, fragments, credentials and HTTP addresses are rejected. A trailing `/`
is normalized away. Leave the field blank to use the existing `site_config.host_name`.

When ngrok changes hostname, open Settings through the new HTTPS address, detect,
review and save it. Do not edit site_config.json for this app-level override.
This setting affects Login Security proxy validation only; other Frappe links,
routing and apps may still use the site-wide host_name.

The local TLS proxy must connect from loopback, forward `X-Forwarded-Proto: https`,
and preserve the public Host or forward `X-Forwarded-Host` equal to the effective
public hostname when rewriting Host to `sriaas.local`. Arbitrary peers and
mismatched forwarded hosts are rejected. Never disable origin checks to fix routing.

If you prefer the site-wide fallback, configure it separately:

```sh
bench --site sriaas.local set-config host_name https://dollop-convent-idly.ngrok-free.dev
bench --site sriaas.local clear-cache
```

Settings: https://dollop-convent-idly.ngrok-free.dev/app/login-security-settings/Login%20Security%20Settings

Users: https://dollop-convent-idly.ngrok-free.dev/app/user

Login: https://dollop-convent-idly.ngrok-free.dev/login

### 4. Configure the WhatsApp sender

As Administrator/System Manager, open **Chat Channel Account** and create or select
the sender intended for login codes:

| Field | Required configuration |
| --- | --- |
| Channel Type | Interakt |
| Is Active | Checked |
| Interakt API Key | Valid account API key, stored in the Password field |
| Interakt Message API URL | `https://api.interakt.ai/v1/public/message/` |

Save the account. Other channel types and nonofficial endpoint URLs are rejected.
Do not put the API key in this README or browser code.

### 5. Configure Login Security Settings

Keep **Activate Login Security for this Site** unchecked while preparing the pilot.
Do not switch off an already active site as a routine setup step; prepare additional
users under its existing policy.

| Field | Value / starting recommendation |
| --- | --- |
| Delivery Channel | WhatsApp |
| Provider | Interakt |
| Channel Account | The active account saved in step 4 |
| Authentication Template | Exact approved provider template name; `otp_verification` only if that is your approved template |
| Template Language | Exact approved language code; the local configured value is `en` |
| Authentication Template Approval Confirmed | Check only after confirming provider approval |
| Code Validity (seconds) | 300; supported range 60?600 |
| Resend Cooldown (seconds) | 60; supported range 30?300 |
| Attempts Per Challenge | 5; supported range 1?10 |
| Sends Per User/Number Per Hour | 5; supported range 1?30 |
| Audit Retention (days) | 30; supported range 7?365 |

Save. Provider validation checks the account and required settings locally; it
cannot prove provider approval or actual delivery. The current adapter sends
one code as the template body value and button index 0 value, so the approved
Authentication template must support that shape.

### 6. Resolve native 2FA and old coverage

1. Inspect **System Settings ? Enable Two Factor Auth**. The custom app refuses
   activation while native 2FA is enabled. Plan an explicit migration before
   replacing an existing requirement; this app never disables native 2FA itself.
2. If **Review Coverage Migration** appears in Login Security Settings, review the
   legacy selected users, reconcile their saved mobile numbers, and verify them.
   Apply the reviewed migration using your operator password. Empty legacy
   coverage migrates automatically.
3. Current coverage is selected on each **User**, not by roles or the Customer
   Number Privacy permissions table.

### 7. Enroll the pilot user's saved mobile number

1. Open the pilot **User** and confirm **Enabled** and **User Type = System User**.
2. Leave **Enable Login Verification** unchecked.
3. Save **Mobile No.** in valid international format with `+` and country code,
   for example `+14155552671` (synthetic example; use the user's real number).
4. Save the User before starting verification.
5. Select **Login Security ? Verify Mobile No.** from the form's action buttons.
6. Enter **your administrator password**, not the staff member's password.
7. Send the code. The server uses that User's saved Mobile No.; the dialog cannot
   override the recipient.
8. Enter the WhatsApp code received by the staff member and choose **Verify number**.
9. Save the ten recovery codes securely and give them privately to that user.
   They are shown once; previous recovery codes are replaced by re-enrollment.
10. Confirm the User shows a verified-number status.
11. Check **Enable Login Verification**, save, and confirm the number is still verified.

A checked User with site activation OFF is prepared but not yet challenged.
A checked User with site activation ON is covered immediately on their next login.
Changing roles does not turn this checkbox on or off.

### 8. Activate and test the pilot

1. Restrict Administrator emergency access and confirm the operator can recover
   an account if needed.
2. On staging, activate for the enrolled pilot and exercise the acceptance checks
   below before widening coverage. Do not mark an unchecked rollout as completed.
3. In Settings, acknowledge **Restricted Administrator Emergency Access Established**
   and **Enrollment, Recovery, Alternate Routes and Session Revocation Checked**
   when those prerequisites have actually been completed.
4. Check **Activate Login Security for this Site** and save. Activation validates
   sender configuration and the enrollments of enabled selected staff.
5. Revoke covered users' existing sessions through your normal Frappe session
   administration procedure during the activation window. This app does not
   automatically revoke or verify existing sessions.
6. Use a private browser window and open the public HTTPS `/login` address.
7. Enter the pilot user's username and password. Expect a WhatsApp code screen,
   not immediate Desk access.
8. Enter the newest correct code. Expect successful sign-in and the intended page.
9. Log out and test a wrong code, resend after cooldown, and a saved recovery code.
10. Confirm a consumed code/recovery code cannot be reused. Test native/API and
    enabled alternate login routes: selected users must not bypass verification.
11. Test delivery outage behavior on staging: covered users must not receive
    password-only fallback. Test an unselected staff user separately: native login
    should remain available under that user's existing policy.
12. After the pilot passes, repeat enrollment and checkbox activation for each user.

### 9. Daily login, recovery, and changing numbers

- Normal login: password ? WhatsApp code ? Desk.
- Resend: wait for the displayed cooldown and use the newest code. Resend replaces
  the old code without resetting attempts or the overall ten-minute transaction.
- Lost WhatsApp access: validate the password, select **Use a recovery code**, and
  enter one unused saved code. Sender misconfiguration can still prevent creating
  the transaction; an operator must repair configuration in that case.
- Change a verified mobile: open User, select **Login Security ? Change Verified
  Number**, confirm the operator password, enter the replacement international
  number, and verify its code. Save the new recovery codes. Do not directly edit
  an enrolled number through User, imports, or REST.
- Per-user opt-out: an authorized operator can uncheck **Enable Login Verification**
  and save. This removes this app's requirement for future logins; handle session
  revocation and the replacement security policy deliberately.
- Revocation: the protected enrollment revoke API requires an authenticated
  operator and password confirmation. Revoking enrollment does not silently
  remove User coverage; re-enroll the selected user before they can log in again.

### 10. Troubleshooting

| Symptom | Check / corrective action |
| --- | --- |
| Reload this page on the site's configured address and try again | Compare browser HTTPS origin, Public Login URL (or `host_name` when blank), loopback proxy peer, forwarded protocol and forwarded host. Deploy the Host-rewrite fix, reload Python, and reopen the correct URL. |
| Secure HTTPS is required | Use the public HTTPS URL; forwarded headers from arbitrary network peers are not trusted. |
| No WhatsApp prompt | Check site activation, User checkbox, System User type, and fresh login. Administrator is exempt; existing sessions are not challenged. |
| Verify Mobile No. button missing | Use an operator account, save the User, reload Desk, confirm the app/custom fields are installed. Administrator/Guest and website users cannot enroll. An already verified user uses Change Verified Number. |
| User checkbox cannot be enabled | Save a valid international number, complete verification, fix sender configuration, and complete any coverage/native-2FA migration. |
| Delivery rejected / unknown | Check active sender, API key, exact Authentication template/language and provider status. Acceptance is not proof of delivery; use recovery or bounded resend. |
| OTP send limit reached | Wait for the indicated time. Enrollment, login and resend share send budgets, including rejected attempts. |
| Invalid / expired code | Use the newest code in the same browser; restart the transaction if expired. |
| Account details changed | Restart login after password, number, enrollment, User or policy changes. |
| Verification unavailable | Check Redis and configuration; review Login Security logs without enabling credential/body logging. |
| Correct password but native/API login denied | Expected for a covered user without custom verification proof; use the shared login page. |

### 11. Verification commands and limits

```sh
cd /home/srdev/frappe-bench-v15
./env/bin/python -m unittest discover -s apps/login_security/login_security/tests -v
```

At the local public-URL verification, 47 tests passed and 28 opt-in site integration
tests were skipped. Requests through the actual ngrok tunnel confirmed that the
correct origin reached authentication and a foreign origin remained rejected.
A full live-provider password/WhatsApp journey still requires the pilot test above.

For an isolated staging site with live enforcement and native 2FA OFF:

```sh
LOGIN_SECURITY_TEST_SITE=<staging-site> ./env/bin/python -m unittest discover -s apps/login_security/login_security/tests -v
```

These integration tests create and remove a temporary principal and mock provider
calls. They skip on an already active site; do not disable live protection simply
to run them. Browser tests and additional operational boundaries are described below.

## Installation reference

From a bench with `frappe` and the matching `wa_chat_hub` code installed:

The WhatsApp dependency resolves from the sibling `apps/wa_chat_hub` directory.
This avoids Frappe v15 trying to find the private/custom app under the public
`frappe` or `erpnext` GitHub organizations during installation.

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
loopback proxy when the request host matches the configured public host or the selected site name,
and the forwarded protocol is `https`. A supplied forwarded host must
also match. It does not trust forwarded headers from arbitrary network peers.
When the local proxy rewrites Host to the selected Frappe site name, an explicit
forwarded host matching the configured HTTPS address is required.
Both login and enrollment binding cookies remain Secure on this path. Browser
Origin/Referer must still match the public site; cross-origin requests are rejected.

### Managed hosting with an internal HTTP proxy

If the public entry point enforces HTTPS but the container Nginx overwrites
`X-Forwarded-Proto` with its internal `http` scheme, an administrator can explicitly
assert that deployment contract using the server-only site setting:

```sh
bench --site <site> set-config login_security_https_enforced_upstream 1 --parse
```

Set Public Login URL to the exact public HTTPS origin first. Use this option only
when the public ingress enforces HTTPS and direct public access to container Nginx
and Gunicorn is prevented. This setting cannot prove TLS at the ingress; the
operator must verify that infrastructure guarantee. Prefer correcting proxy headers
when hosting permits it. Do not use this option for publicly reachable HTTP sites.

The option defaults off. It only recognizes requests from a loopback connection
with a matching public Host (or the site Host plus an exact forwarded public Host).
Browser Origin/Referer must still match the public HTTPS origin. Remote peers,
foreign hosts and malformed forwarded-protocol lists are rejected. Login and
enrollment binding cookies remain Secure. Existing forwarded-HTTPS behavior stays
available without the opt-in. Container/private proxy peers remain unsupported.

Deploy the updated Python code and restart managed web processes using the hosting
platform's deployment/restart mechanism. No DocType migration or frontend rebuild
is required for this option. Test enrollment, OTP login and recovery on staging.
To remove the override, set the option to `0` with `--parse`; requests then require
normal HTTPS recognition again. Never rotate the site encryption key for this fix.

If enforcement is disabled or a user is outside coverage, the browser delegates
to the native login handler, preserving existing native 2FA/reset behavior.

The trusted public origin uses **Public Login URL** when saved, otherwise the site's
`host_name`. Detection is an operator-reviewed settings action, not automatic
learning from login requests.

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

## Customer number privacy

When Customer Number Privacy is enabled, restricted users see only the verified
phone suffix in Login Security workflows. Raw Login Security Enrollment records
cannot be opened, printed, exported, or queried through generic HTTP APIs without
full-number visibility. OTP delivery, enrollment verification, recovery codes,
and internal policy checks continue to use the original phone value.


## Browser request diagnostics

After deploying and restarting web processes, rebuild `login_security` assets and
reload Desk. On a saved User, Administrator/System Manager can select
**Login Security > Check Login Request**. This sends an authenticated POST through
the same browser/proxy path as enrollment, with the same Login Security and CSRF
headers, but never starts enrollment, sends messages or changes settings.

Copy the JSON report: `validation` runs the actual request gate, while `checks`
shows the proxy recognition conditions. Proxy checks are informational when the
request already arrives as HTTPS. The report includes a diagnostic version, the
loaded HTTPS override, configured/resolved origins and selected request metadata.
No passwords, tokens, cookies, phone numbers, Referer paths or query strings are
included. It is deliberately accessible even when origin recognition fails;
normal authentication, operator permissions and Frappe CSRF handling still apply.


The v2 request diagnostic retains the raw Host and adds `normalized_proxy_host`.
Identical comma-separated public Host values from a loopback proxy are collapsed
only when every element equals the configured public host. Mixed hosts, empty
entries, duplicate internal site names and remote peers remain rejected. The
HTTPS override is still required when the proxy forwards `http`. Fix duplicate
Nginx Host directives when possible; this compatibility handling affects only
Login Security origin checks, not Frappe routing or other apps.
