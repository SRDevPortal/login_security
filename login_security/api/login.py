import hmac
import secrets

import frappe

from login_security import audit, policy, providers
from login_security.crypto import new_code
from login_security.enforcement import authorize
from login_security.runtime import COOKIE, LoginSecurityError, binding, endpoint, request_scheme, store


@frappe.whitelist(allow_guest=True, methods=["GET"])
def configuration():
    # Public capability only; never expose recipients, credentials or coverage lists.
    return {"enabled": bool(policy.settings().enabled)}


def guest_only():
    if frappe.session.user != "Guest":
        raise LoginSecurityError("session", "Sign out before starting a new login.")


def send_limits(storage, config, user, phone):
    storage.rate("send_user", user, int(config.send_limit), 3600)
    storage.rate("send_phone", phone, int(config.send_limit), 3600)
    storage.rate("send_ip", frappe.local.request_ip, 60, 3600)


def public_challenge(challenge_id, data, config, outcome):
    return {
        "status": "challenge",
        "challenge_id": challenge_id,
        "destination": "WhatsApp ending " + data["phone"][-4:],
        "expires_in": max(0, data["expires_at"] - int(store().clock())),
        "resend_after": int(config.resend_cooldown),
        "delivery": outcome,
    }


def deliver(storage, config, challenge_id, data, code):
    result = providers.send(config, data["phone"], code, challenge_id)
    if result["outcome"] == "rejected":
        # Invalidate this code, but retain the password-validated transaction for recovery/resend.
        storage.invalidate_code(challenge_id, code)
    audit.record(data["user"], "delivery", result["outcome"], challenge_id)
    return public_challenge(challenge_id, data, config, result["outcome"])


@frappe.whitelist(allow_guest=True, methods=["POST"])
@endpoint
def start(usr=None, pwd=None):
    guest_only()
    if not isinstance(usr, str) or len(usr) > 320 or not isinstance(pwd, str) or len(pwd) > 512:
        raise frappe.AuthenticationError
    config = policy.settings()
    if not config.enabled:
        return {"status": "native_login"}
    storage = store()
    storage.rate("start_ip", frappe.local.request_ip, 60, 600)
    storage.rate("start_identifier", str(usr).lower(), 10, 600)
    if not isinstance(usr, str) or not isinstance(pwd, str) or not usr or not pwd:
        raise frappe.AuthenticationError
    manager = frappe.local.login_manager
    manager.authenticate(user=usr, pwd=pwd)
    user = manager.user
    # Native login is performed by the original client handler, preserving native 2FA/reset flows.
    if not policy.covered(user, config):
        return {"status": "native_login"}
    policy.account_checks(manager)
    row = policy.enrollment(user)
    providers.validate_provider(config)
    send_limits(storage, config, user, row.phone)
    nonce, code = secrets.token_urlsafe(32), new_code()
    challenge_id, data = storage.create(
        purpose="staff_login",
        binding=nonce,
        code=code,
        context={"user": user, "phone": row.phone, "fingerprint": policy.fingerprint(user, config)},
        ttl=int(config.code_ttl),
        max_attempts=int(config.max_attempts),
    )
    frappe.local.cookie_manager.set_cookie(
        COOKIE,
        nonce,
        httponly=True,
        samesite="Strict",
        secure=request_scheme() == "https",
        max_age=600,
    )
    audit.record(user, "challenge", "created", challenge_id)
    return deliver(storage, config, challenge_id, data, code)


def current_challenge(challenge_id):
    guest_only()
    storage, nonce, config = store(), binding(), policy.settings()
    data = storage.read(challenge_id, nonce, "staff_login")
    if not policy.covered(data["user"], config):
        raise LoginSecurityError("changed", "Login policy changed. Restart login.")
    if not hmac.compare_digest(data["fingerprint"], policy.fingerprint(data["user"], config)):
        storage.cancel(challenge_id)
        raise LoginSecurityError("changed", "Account details changed. Restart login.")
    manager = frappe.local.login_manager
    manager.user = data["user"]
    policy.account_checks(manager)
    return storage, nonce, config, data, manager


@frappe.whitelist(allow_guest=True, methods=["POST"])
@endpoint
def verify(challenge_id=None, code=None):
    storage, nonce, _config, data, manager = current_challenge(challenge_id)
    storage.rate("verify_user", data["user"], 20, 600)
    storage.rate("verify_ip", frappe.local.request_ip, 100, 600)
    if not isinstance(code, str) or len(code) > 128:
        code = ""
    try:
        storage.verify(challenge_id, nonce, "staff_login", code)
    except Exception:
        audit.record(data["user"], "verification", "denied", challenge_id)
        raise
    return finish(manager, challenge_id, "otp")


def finish(manager, challenge_id, factor):
    # Called only after atomic factor consumption, never exposed as a whitelisted method.
    policy.account_checks(manager)
    audit.record(manager.user, "verification", factor + "_accepted", challenge_id)
    authorize(manager.user)
    try:
        manager.post_login()
    finally:
        frappe.local.login_security_proof = None
    frappe.local.cookie_manager.delete_cookie(COOKIE)
    # Frappe sets top-level message/home_page. Clear its message before the handler serializes our result.
    frappe.local.response.pop("message", None)
    from urllib.parse import urlsplit

    destination = frappe.local.response.get("home_page") or "/app"
    parsed = urlsplit(destination)
    if parsed.netloc or parsed.scheme or not destination.startswith("/") or "\\" in destination:
        destination = "/app"
    return {"status": "logged_in", "home_page": destination}


@frappe.whitelist(allow_guest=True, methods=["POST"])
@endpoint
def resend(challenge_id=None):
    storage, nonce, config, data, _manager = current_challenge(challenge_id)
    send_limits(storage, config, data["user"], data["phone"])
    code = new_code()
    data = storage.resend(
        challenge_id,
        nonce,
        "staff_login",
        code,
        cooldown=int(config.resend_cooldown),
        ttl=int(config.code_ttl),
    )
    return deliver(storage, config, challenge_id, data, code)


@frappe.whitelist(allow_guest=True, methods=["POST"])
@endpoint
def recover(challenge_id=None, recovery_code=None):
    storage, nonce, _config, data, manager = current_challenge(challenge_id)
    storage.rate("recovery_user", data["user"], 5, 3600)
    storage.rate("recovery_ip", frappe.local.request_ip, 30, 3600)
    from login_security.enrollment import consume_recovery

    if not isinstance(recovery_code, str) or len(recovery_code) > 128:
        raise frappe.AuthenticationError
    # Redis transaction consumption is atomic independently of the database recovery-code lock.
    # If a later step fails, the challenge stays consumed and must be restarted.
    consume_recovery(data["user"], recovery_code)
    try:
        storage.consume_for_recovery(challenge_id, nonce)
    except Exception:
        frappe.db.rollback()
        raise
    return finish(manager, challenge_id, "recovery")
