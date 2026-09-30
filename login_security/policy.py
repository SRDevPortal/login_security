import frappe
from frappe.auth import validate_ip_address
from frappe.twofactor import should_run_2fa

from login_security.crypto import digest, normalize_phone
from login_security.runtime import LoginSecurityError, secret


def settings():
    return frappe.get_single("Login Security Settings")


def covered(user, config=None):
    config = config or settings()
    # Explicit emergency policy. This is documented and acknowledged before activation.
    if not config.enabled or user in ("Guest", "Administrator"):
        return False
    if frappe.db.get_value("User", user, "user_type") != "System User":
        return False
    if int(config.get("coverage_version") or 0) >= 2:
        # Readiness is deliberately separate: missing enrollment must never turn coverage off.
        return bool(frappe.db.get_value("User", user, "login_security_enabled"))
    return legacy_selected(user, config)


def legacy_selected(user, config):
    """Retain v1 coverage until an explicit, atomic migration has completed."""
    return bool(
        config.all_staff
        or user in {r.user for r in config.users}
        or set(frappe.get_roles(user)) & {r.role for r in config.roles}
    )


def enrollment(user, require_current_mobile=None):
    row = frappe.db.get_value(
        "Login Security Enrollment",
        user,
        ["name", "phone", "verified_at", "modified", "enabled"],
        as_dict=True,
    )
    if not row or not row.enabled or not row.verified_at:
        raise LoginSecurityError(
            "enrollment", "WhatsApp verification is not enrolled. Contact your administrator."
        )
    if require_current_mobile is None:
        require_current_mobile = int(settings().get("coverage_version") or 0) >= 2
    if require_current_mobile:
        try:
            mobile = normalize_phone(frappe.db.get_value("User", user, "mobile_no") or "")
        except ValueError:
            raise LoginSecurityError(
                "enrollment", "Your Mobile No. needs verification. Contact your administrator."
            ) from None
        if mobile != row.phone:
            raise LoginSecurityError(
                "enrollment",
                "Your Mobile No. no longer matches the verified number. Contact your administrator.",
            )
    return row


def account_checks(manager):
    user = manager.user
    if not frappe.db.get_value("User", user, "enabled"):
        raise frappe.AuthenticationError
    if frappe.get_system_settings("disable_user_pass_login"):
        raise LoginSecurityError("password_disabled", "Password login is disabled on this site.")
    if manager.force_user_to_reset_password():
        raise LoginSecurityError(
            "password_expired", "Reset your password using Forgot Password, then sign in again."
        )
    # Initial release deliberately refuses overlapping native factors, never skips them.
    if should_run_2fa(user):
        raise LoginSecurityError(
            "native_2fa",
            "Your existing two-factor method requires an administrator migration before WhatsApp login.",
        )
    validate_ip_address(user)
    manager.validate_hour()


def fingerprint(user, config=None):
    config = config or settings()
    auth = frappe.db.sql(
        """select password from `__Auth`
        where doctype='User' and name=%s and fieldname='password' and encrypted=0""",
        (user,),
    )
    if not auth:
        raise frappe.AuthenticationError
    row = enrollment(user)
    user_state = frappe.db.get_value(
        "User", user, ["mobile_no", "login_security_enabled", "modified"], as_dict=True
    )
    return digest(
        secret(),
        "account",
        frappe.local.site,
        user,
        auth[0][0],
        str(row.modified),
        row.phone,
        str(config.modified),
        user_state.mobile_no,
        int(user_state.login_security_enabled or 0),
        str(user_state.modified),
    )


def validate_settings(doc):
    previous = doc.get_doc_before_save()
    if previous:
        for field in ("coverage_version", "coverage_migration_snapshot"):
            if doc.get(field) != previous.get(field):
                frappe.throw("Coverage migration fields are managed by the migration workflow.")
        if int(doc.get("coverage_version") or 0) >= 2:
            before = (previous.all_staff, [r.user for r in previous.users], [r.role for r in previous.roles])
            after = (doc.all_staff, [r.user for r in doc.users], [r.role for r in doc.roles])
            if before != after:
                frappe.throw("Manage login verification on each User record. Legacy selectors are retired.")
    for field, low, high in (
        ("code_ttl", 60, 600),
        ("resend_cooldown", 30, 300),
        ("max_attempts", 1, 10),
        ("send_limit", 1, 30),
        ("audit_retention_days", 7, 365),
    ):
        if not low <= int(doc.get(field) or 0) <= high:
            frappe.throw(f"{field} must be between {low} and {high}.")
    if not doc.enabled:
        return
    secret()
    if not doc.emergency_access_acknowledged or not doc.rollout_checks_completed:
        frappe.throw("Complete the rollout checks and acknowledge restricted Administrator emergency access.")
    if frappe.get_system_settings("enable_two_factor_auth"):
        frappe.throw(
            "Native 2FA is enabled. Resolve the migration policy first; Login Security will not disable it."
        )
    from login_security.providers import validate_provider

    try:
        validate_provider(doc)
    except (LoginSecurityError, ValueError):
        frappe.throw("Configure an active Interakt sender and an approved authentication template.")
    candidates = frappe.get_all("User", filters={"enabled": 1, "user_type": "System User"}, pluck="name")
    for user in candidates:
        if covered(user, doc):
            try:
                enrollment(user, require_current_mobile=int(doc.get("coverage_version") or 0) >= 2)
            except LoginSecurityError:
                frappe.throw("Verify the current Mobile No. of every selected User before site activation.")
