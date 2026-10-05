"""User extensions owned entirely by Login Security; no core DocType edits."""

import frappe
from frappe.utils import cint

from login_security import audit, policy, providers
from login_security.crypto import normalize_phone
from login_security.runtime import LoginSecurityError

_NUMBER_CHANGE = object()


def is_operator():
    actor = frappe.session.user
    return actor == "Administrator" or (actor != "Guest" and "System Manager" in frappe.get_roles(actor))


def comparable_phone(value):
    try:
        return normalize_phone(value or "")
    except ValueError:
        return (value or "").strip()


def validate_user(doc, method=None):
    previous = doc.get_doc_before_save()
    old_flag = cint(previous.get("login_security_enabled")) if previous else 0
    new_flag = cint(doc.get("login_security_enabled"))
    flag_changed = old_flag != new_flag
    if flag_changed and not is_operator():
        raise frappe.PermissionError("Only a System Manager can change login verification.")
    if new_flag and not (doc.mobile_no or "").strip():
        frappe.throw(
            "Mobile No. is required when Enable Login Verification is enabled.",
            frappe.MandatoryError,
        )
    if new_flag and (doc.name in ("Guest", "Administrator") or doc.user_type != "System User"):
        frappe.throw(
            "Login verification is available for staff accounts only. Administrator uses restricted emergency login."
        )
    old_mobile = comparable_phone(previous.mobile_no) if previous else ""
    new_mobile = comparable_phone(doc.mobile_no)
    if previous and old_mobile != new_mobile:
        enrolled = frappe.db.exists("Login Security Enrollment", doc.name)
        if (old_flag or new_flag or enrolled) and doc.flags.get(
            "login_security_number_change"
        ) is not _NUMBER_CHANGE:
            frappe.throw("Use Change Verified Number in the Login Security section to change this Mobile No.")
    reenabling = previous and not previous.enabled and doc.enabled
    if new_flag and (flag_changed or reenabling):
        config = policy.settings()
        if int(config.get("coverage_version") or 0) < 2:
            frappe.throw("Complete the Login Security coverage migration first.")
        if doc.is_new():
            frappe.throw("Save this User, verify their Mobile No., then enable login verification.")
        try:
            mobile = normalize_phone(doc.mobile_no or "")
        except ValueError:
            frappe.throw(
                "Keep Enable Login Verification unchecked, save Mobile No. in international format "
                "with + and country code, then use Login Security > Verify Mobile No."
            )
        try:
            row = policy.enrollment(doc.name, require_current_mobile=True)
            if mobile != row.phone:
                raise ValueError
        except (LoginSecurityError, ValueError):
            frappe.throw(
                "This User's current Mobile No. has not been verified. Keep Enable Login Verification "
                "unchecked and save the User. Then use Login Security > Verify Mobile No., enter the "
                "WhatsApp code, and enable login verification after verification succeeds."
            )
        try:
            providers.validate_provider(config)
        except (LoginSecurityError, ValueError, frappe.DoesNotExistError):
            frappe.throw(
                "The login verification sender is not configured correctly. Open Login Security Settings "
                "and configure an active Interakt Channel Account with an approved Authentication "
                "template and language before enabling login verification."
            )
        from frappe.twofactor import should_run_2fa

        if should_run_2fa(doc.name):
            frappe.throw(
                "Resolve this User's existing native two-factor requirement before enabling this method."
            )


def audit_user_change(doc, method=None):
    previous = doc.get_doc_before_save()
    if previous and cint(previous.get("login_security_enabled")) != cint(doc.get("login_security_enabled")):
        audit.record(
            doc.name, "user_policy", "enabled" if cint(doc.get("login_security_enabled")) else "disabled"
        )


@frappe.whitelist(methods=["GET"])
def status(user):
    if frappe.session.user != user and not is_operator():
        raise frappe.PermissionError
    doc = frappe.db.get_value(
        "User", user, ["name", "user_type", "mobile_no", "login_security_enabled"], as_dict=True
    )
    if not doc:
        raise frappe.DoesNotExistError
    config = policy.settings()
    supported = user not in ("Administrator", "Guest") and doc.user_type == "System User"
    row = frappe.db.get_value(
        "Login Security Enrollment", user, ["phone", "verified_at", "enabled"], as_dict=True
    )
    verified = bool(row and row.enabled and row.verified_at and row.phone == comparable_phone(doc.mobile_no))
    if not supported:
        label = "Native emergency access" if user == "Administrator" else "Staff accounts only"
    elif int(config.get("coverage_version") or 0) < 2:
        label = "Legacy coverage — migration review required"
    elif doc.login_security_enabled and not verified:
        label = "Action required — Mobile No. is not verified"
    elif doc.login_security_enabled:
        label = "Verification enabled" if config.enabled else "Prepared — site verification is inactive"
    else:
        label = "Number verified — login verification is off" if verified else "Not enrolled"
    return {
        "label": label,
        "supported": supported,
        "can_manage": is_operator(),
        "enrolled": bool(row),
        "verified": verified,
        "site_active": bool(config.enabled),
        "coverage_version": int(config.get("coverage_version") or 0),
        "destination": (
            "WhatsApp ending " + (row.phone if row else comparable_phone(doc.mobile_no))[-4:]
            if (row and row.phone) or doc.mobile_no
            else None
        ),
        "verified_at": str(row.verified_at) if row and row.verified_at else None,
    }
