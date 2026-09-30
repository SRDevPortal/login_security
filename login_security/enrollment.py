"""Administrator-assisted number possession verification and one-use recovery codes."""

import hmac
import json
import secrets

import frappe
from frappe.utils import now_datetime
from frappe.utils.password import check_password

from login_security import audit, policy, providers
from login_security.crypto import digest, new_code, normalize_phone
from login_security.runtime import (
    COOKIE,
    LoginSecurityError,
    binding,
    endpoint,
    request_scheme,
    secret,
    store,
)

_WRITE_TOKEN = object()


def require_operator(password=None):
    actor = frappe.session.user
    if actor == "Guest" or (actor != "Administrator" and "System Manager" not in frappe.get_roles(actor)):
        raise frappe.PermissionError
    if password is not None:
        from frappe.auth import get_login_attempt_tracker

        tracker = get_login_attempt_tracker(actor)
        try:
            check_password(actor, password, delete_tracker_cache=False)
        except frappe.AuthenticationError:
            tracker.add_failure_attempt()
            raise
    return actor


@frappe.whitelist(methods=["POST"])
@endpoint
def begin(user=None, phone=None, password=None):
    if phone is not None:
        raise LoginSecurityError(
            "phone", "Verify the saved User Mobile No.; use Change Verified Number for replacements."
        )
    return start_enrollment(user, password)


@frappe.whitelist(methods=["POST"])
@endpoint
def begin_change(user=None, new_phone=None, password=None):
    return start_enrollment(user, password, new_phone=new_phone, changing=True)


def target_state(user, lock=False):
    if not isinstance(user, str) or not user or len(user) > 320:
        raise frappe.AuthenticationError
    row = frappe.db.get_value(
        "User", user, ["mobile_no", "modified", "enabled", "user_type"], as_dict=True, for_update=lock
    )
    if not row or not row.enabled or row.user_type != "System User" or user in ("Guest", "Administrator"):
        raise frappe.AuthenticationError
    enrollment = frappe.db.get_value("Login Security Enrollment", user, "modified", for_update=lock)
    return row, digest(secret(), "enrollment-state", user, row.mobile_no, str(row.modified), str(enrollment))


def start_enrollment(user, password, new_phone=None, changing=False):
    actor = require_operator()
    storage, config = store(), policy.settings()
    storage.rate("enrollment_operator", actor, 10, 3600)
    require_operator(password or "")
    target, state = target_state(user)
    try:
        phone = normalize_phone(new_phone if changing else target.mobile_no)
    except ValueError as exc:
        raise LoginSecurityError("phone", str(exc)) from None
    if frappe.db.exists("Login Security Enrollment", {"phone": phone, "user": ("!=", user)}):
        raise LoginSecurityError("phone", "This destination is already enrolled for another user.")
    from login_security.api.login import public_challenge, send_limits

    providers.validate_provider(config)
    send_limits(storage, config, user, phone)
    nonce, code = secrets.token_urlsafe(32), new_code()
    challenge_id, data = storage.create(
        purpose="enrollment",
        binding=nonce,
        code=code,
        context={"user": user, "phone": phone, "operator": actor, "state": state, "changing": changing},
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
    result = providers.send(config, phone, code, challenge_id)
    if result["outcome"] == "rejected":
        storage.cancel(challenge_id)
    audit.record(user, "enrollment_delivery", result["outcome"], challenge_id)
    return public_challenge(challenge_id, data, config, result["outcome"])


@frappe.whitelist(methods=["POST"])
@endpoint
def complete(challenge_id=None, code=None):
    actor = require_operator()
    storage, nonce = store(), binding()
    data = storage.read(challenge_id, nonce, "enrollment")
    if data["operator"] != actor:
        raise frappe.PermissionError
    _, current_state = target_state(data["user"], lock=True)
    if not hmac.compare_digest(current_state, data.get("state", "")):
        raise LoginSecurityError("changed", "User or enrollment changed. Start number verification again.")
    storage.rate("enrollment_verify", actor, 20, 600)
    if not isinstance(code, str) or len(code) > 128:
        code = ""
    data = storage.verify(challenge_id, nonce, "enrollment", code)
    if not frappe.db.get_value("User", data["user"], "enabled"):
        raise frappe.AuthenticationError
    recovery_codes = [secrets.token_hex(16) for _ in range(10)]
    doc = (
        frappe.get_doc("Login Security Enrollment", data["user"])
        if frappe.db.exists("Login Security Enrollment", data["user"])
        else frappe.new_doc("Login Security Enrollment")
    )
    doc.update(
        {
            "user": data["user"],
            "phone": data["phone"],
            "enabled": 1,
            "verified_at": now_datetime(),
            "verified_by": actor,
            "recovery_hashes": json.dumps([recovery_digest(data["user"], c) for c in recovery_codes]),
        }
    )
    doc.flags.login_security_write = _WRITE_TOKEN
    doc.save(ignore_permissions=True)
    if data.get("changing"):
        from login_security.user_policy import _NUMBER_CHANGE

        user_doc = frappe.get_doc("User", data["user"])
        user_doc.mobile_no = data["phone"]
        user_doc.flags.login_security_number_change = _NUMBER_CHANGE
        user_doc.save(ignore_permissions=True)
    audit.record(data["user"], "enrollment", "verified", challenge_id)
    frappe.local.cookie_manager.delete_cookie(COOKIE)
    return {"status": "enrolled", "recovery_codes": recovery_codes}


def recovery_digest(user, code):
    return digest(secret(), "recovery", frappe.local.site, user, code.strip())


def consume_recovery(user, code):
    rows = frappe.db.sql(
        """select recovery_hashes from `tabLogin Security Enrollment`
                           where name=%s and enabled=1 for update""",
        (user,),
    )
    hashes = json.loads(rows[0][0] or "[]") if rows else []
    expected = recovery_digest(user, code)
    index = next((i for i, value in enumerate(hashes) if hmac.compare_digest(value, expected)), None)
    if index is None:
        raise frappe.AuthenticationError
    hashes.pop(index)
    # Does not change enrollment version; another password-authenticated challenge may use a different code.
    frappe.db.set_value(
        "Login Security Enrollment", user, "recovery_hashes", json.dumps(hashes), update_modified=False
    )


@frappe.whitelist(methods=["POST"])
@endpoint
def revoke(user=None, password=None):
    actor = require_operator()
    store().rate("enrollment_revoke", actor, 10, 3600)
    require_operator(password or "")
    frappe.db.set_value("Login Security Enrollment", user, {"enabled": 0, "recovery_hashes": "[]"})
    audit.record(user, "enrollment", "revoked")
    return {"status": "revoked"}
