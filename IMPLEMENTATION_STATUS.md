# Login Security — Implementation Status

Updated: 2026-09-29.

## Delivered user-level revision

Implemented **Enable Login Verification** on each **User** record and
OTP delivery to that User's verified **Mobile No. (`mobile_no`)**. The revised
[implementation plan](../../WHATSAPP_OTP_LOGIN_IMPLEMENTATION_PLAN.md) replaces
settings-based user/role/all-staff selection with the User checkbox, keeps shared
sender/rate settings, and specifies verified-number matching and safe migration.

All User customization is owned by `login_security`: four database Custom Fields,
User form JavaScript and validation hooks. No core User source edits were needed.
Local empty legacy coverage migrated to version 2 without selecting any staff or
activating enforcement. Nonempty legacy coverage requires a reviewed migration.
The results below validate the updated per-user implementation.

## Delivered

The initial implementation is present in `apps/login_security`, installed on local
`site1.local`, and registered in the local bench. **Enforcement is disabled.**
No remote deployment, live WhatsApp message, production policy change or staff
enrollment was performed.

Implemented:

- Organization-neutral `login_security` app, module, DocTypes and API namespace.
- User-level verification checkbox, computed status, Verify Mobile No. and
  Change Verified Number actions; shared settings for sender, limits and activation.
- Protected number replacement updates User and enrollment together only after
  OTP verification. Ordinary document edits cannot redirect an enrolled number.
- Legacy coverage remains enforced until an unchanged, ready migration review is
  applied. Hidden legacy selectors are retained as history.
- Password-first login endpoints, browser binding, site/purpose-bound HMACs,
  Redis expiry, atomic verification/resend and independent rolling limits.
- Server-side guard before normal Frappe session creation; a client-supplied
  flag cannot satisfy verification.
- Rechecks for account status, password hash, enrollment version, policy changes,
  native 2FA, password expiry and login IP/hour restrictions.
- Shared ERP/CRM login-page extension, resend, recovery and safe local redirects.
- Administrator-assisted possession-verified enrollment and restricted enrollment
  writes. Single-use recovery codes are displayed once and stored as keyed digests.
- Dedicated Interakt Authentication-template sender in
  `wa_chat_hub/wa_chat_hub/authentication.py`. No chat creation, AI processing,
  provider-response logging or automatic retry.
- Redacted audit events, retention cleanup and safe inventory command.
- Documentation for setup, pilot checks, future SMS delivery and rollback.

`sriaas_role_permissions` was not edited by this work. An unrelated existing
working-tree modification in its `setup/runner.py` was left untouched. Framework,
ERPNext and CRM source files were not changed.

## Actual implementation layout

The planning document's original module breakdown was consolidated where useful:

| File | Responsibility |
|---|---|
| `api/login.py` | Configuration capability, start, verify, resend and recovery endpoints |
| `challenges.py` | Redis storage, rate limits and atomic state transitions |
| `crypto.py` | Keyed digests, code generation and phone normalization |
| `runtime.py` | Request/origin checks, cookie binding, error boundary and no-store responses |
| `policy.py` | Coverage, activation validation, account checks and challenge version binding |
| `user_policy.py` | User checkbox permissions, number guards and computed status |
| `install.py`, `patches/`, `coverage_migration.py` | App-owned User fields and legacy coverage migration |
| `enforcement.py` | Internal proof and pre-session enforcement |
| `enrollment.py` | Administrator-assisted enrollment, revocation and recovery-code consumption |
| `providers.py` | Channel/provider boundary for WhatsApp now and future SMS |
| `audit.py` | Minimal authentication events and retention |
| `diagnostics.py` | Read-only site inventory without secrets or phone numbers |
| `public/js/login.js` | Shared login UI extension |
| `public/js/user.js` | User enrollment and staged number replacement actions |
| `login_security/doctype/` | Settings, enrollment, events and coverage child tables |

Five DocTypes were installed. An initial schema sync encountered stale bench module
cache; clearing that cache and rerunning the targeted install completed successfully.
The settings remain disabled after installation.

## Verification performed

All **48 Python tests** passed together on the local development environment:

- 12 challenge tests using a disposable Redis server, including expiry, attempt
  exhaustion, resend invalidation, cross-site/browser binding, outage behavior and
  24 concurrent attempts with exactly one successful consumption.
- 4 mocked Interakt tests for payload consistency, timeout/rejection redaction and
  rejection of arbitrary provider endpoints.
- 4 enforcement tests, including the real Frappe `post_login()` call order and
  rejection of client-like or wrong-user proof.
- 28 real Frappe WSGI/site tests: authenticated session issuance only after OTP,
  native login denial, invalid password, foreign browser, incorrect code, recovery
  replay, request origin, asset inclusion, native 2FA conflict, disabled user,
  password changes, email-link denial, uncertain delivery, enrollment write guard,
  enrollment version changes, HTTPS enforcement and administrator enrollment;
  checkbox invalidation, mismatched numbers, unauthorized document edits,
  recipient override rejection, staged replacement, stale replacement rejection,
  idempotent custom fields, migration readiness/stale review, transactional rollback,
  independent User flags/destinations, enrollment required before enabling and
  mandatory Mobile No. on every save while verification is enabled.

The real-site tests used a temporary principal, mocked all provider calls, kept
persisted enforcement disabled, and removed their temporary user and enrollment.
The site returned to its original eight enabled staff accounts after testing.

All **10 browser scenarios** passed in headless Chrome using the real frontend scripts
with mocked APIs: leading-zero OTP and CRM redirect, recovery and external redirect
rejection, resend and safe error rendering, disabled-policy native behavior, and
native delegation for uncovered users. Five User-form scenarios cover safe status
display, saved-number enrollment, staged replacement, ordinary-user restrictions
and the conditional Mobile No. requirement.
These use mocked APIs and a minimal form/dialog harness, not a full Desk browser
journey or a live-provider browser test.

Also passed:

- Python lint and formatting checks on new app files and the delivery adapter.
- Python compilation and JavaScript syntax checks.
- `bench build --app login_security`.
- Final local inventory: app installed, enforcement off, native 2FA unchanged/off,
  existing email-link setting unchanged/on, Redis available.

Custom-app source review found CRM demo and invitation login calls using the
guarded Frappe lifecycle. Their full onboarding journeys remain pilot acceptance
checks. The enabled email-link route was explicitly tested and denied for a
covered user without proof.

## Required before activation

### Subsequent fixes on the active local site

- Split User activation errors into invalid phone format, missing number
  verification and sender configuration, with four focused validation tests.
- Fixed HTTPS origin validation behind the existing loopback ngrok proxy using
  the configured public host, preserving cross-origin rejection and Secure binding
  cookies. Six focused proxy/origin tests cover trusted forwarding, untrusted peers,
  mismatched hosts, direct HTTPS, local development and public HTTP rejection.
- Latest run: 30 unit tests passed; 28 site tests were skipped because this run did
  not opt into live-site integration testing. Earlier site/browser results above
  remain historical. The site's now-enabled enforcement was not changed.
- Empty POST probes through the public ngrok URL passed the same-origin check and
  rejected a foreign origin. No passwords or OTPs were submitted or messages sent.

1. Configure and confirm an approved Interakt Authentication template and sender.
2. Conduct an explicitly authorized live delivery test with a test recipient.
3. Enroll the selected staff, privately distribute recovery codes and test recovery.
4. Review every enabled alternate login/onboarding flow for the target deployment.
5. Restrict `Administrator`, which deliberately retains native emergency login.
6. Plan revocation of existing covered sessions. The app does not retroactively
   verify or automatically revoke them.
7. Confirm HTTPS/proxy settings, provider budget, audit retention and support owner.
8. Enable only the pilot group after completing the activation checklist.

## Current limits

- SMS and other delivery channels are not implemented yet.
- Native 2FA coexistence/migration is not automated. Activation refuses a site
  with native 2FA enabled, and runtime checks refuse overlapping native factors.
- Existing sessions and API/service tokens remain separate from this login gate.
- Custom code creating sessions outside `LoginManager.post_login()` requires a
  deployment-specific review.
- Enrollment is administrator-assisted. No self-service phone change or email
  fallback is provided.
- Provider acceptance is not delivery; webhooks are not used to authenticate users.
- Live WhatsApp delivery and a real-provider browser journey have not been tested.
- Nothing has been pushed to GitHub or deployed to a remote site.
