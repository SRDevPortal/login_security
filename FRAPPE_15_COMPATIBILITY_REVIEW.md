# Frappe 15 compatibility review

Reviewed locally on 2026-09-29 against Frappe **15.108.0**.

## Result

The app is compatible with the inspected Frappe 15.108.0 installation. This is
not a certification of every Frappe 15 patch release or every deployment topology.
The package declares Frappe >=15.0.0,<16.0.0 and Python >=3.10.

## Checks performed

- All 32 unit tests passed, including challenge replay/concurrency, delivery
  redaction, pre-session enforcement, validation messages and proxy-origin checks.
- All 14 browser scenarios passed: nine login scenarios and five User-form
  scenarios. These use mocked API responses; they do not send WhatsApp messages.
- Python lint and formatting checks passed.
- Inspected the installed Frappe source: on_login precedes session creation;
  on_session_creation and after_request support the app's handlers; database
  get_value/get_singles_dict support the locking arguments used by the app.
- User extensions use Custom Fields, doctype_js and doc_events from login_security.
  No core source changes are required.
- Frappe supplies phonenumbers and redis; the installed wa_chat_hub supplies the
  authentication transport. Both apps are declared as required apps.
- Site inventory: app installed, Redis available, coverage version 2, four User
  Custom Fields, site enforcement active and one User selected for verification.
- Both /login and /#login are covered by the current frontend.

## Scope and remaining limits

The 28 live-site integration cases were not rerun: their suite deliberately skips
when persisted enforcement is enabled. Historical integration results are in
IMPLEMENTATION_STATUS.md. Run the suite on a staging site with enforcement off
before deployment to another environment; do not disable production protection
just to run tests.

The current delivery implementation requires the matching
wa_chat_hub.authentication module and an approved Interakt Authentication template.
SMS is not implemented. Installing login_security alone is insufficient.

Native Frappe 2FA coexistence is deliberately rejected. Administrator remains the
documented emergency exception. Existing sessions and API tokens are outside the
new-login OTP gate. Custom apps creating sessions outside Frappe's standard login
lifecycle need a separate review.

The HTTPS tunnel fallback trusts only a loopback proxy with the exact configured
HTTPS host. Other proxy topologies need appropriate trusted-proxy configuration.
Database SQL and runtime behavior were reviewed for this installation, not tested
across other database engines or older Frappe 15 releases.

No credentials, OTPs or provider messages were sent during this compatibility
review. Active settings and user permissions were left unchanged.
