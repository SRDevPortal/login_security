"""Preserve legacy coverage until reviewed; only empty policies migrate unattended."""

import json

import frappe

from login_security import policy
from login_security.crypto import digest
from login_security.runtime import LoginSecurityError, endpoint, secret


def preview(lock=False):
    config = policy.settings()
    if int(config.get("coverage_version") or 0) >= 2:
        return {"version": 2, "users": [], "review_token": None}
    selected = []
    evidence = []
    for user in frappe.get_all("User", filters={"user_type": "System User"}, pluck="name", order_by="name"):
        if lock:
            # User saves acquire this same row lock. Lock before deciding role coverage.
            frappe.db.get_value("User", user, "name", for_update=True)
        if user in ("Guest", "Administrator") or not policy.legacy_selected(user, config):
            continue
        raw = frappe.db.get_value("User", user, ["mobile_no", "modified"], as_dict=True, for_update=lock)
        enrollment = frappe.db.get_value(
            "Login Security Enrollment", user, ["phone", "modified"], as_dict=True, for_update=lock
        )
        ready = True
        try:
            policy.enrollment(user, require_current_mobile=True)
        except LoginSecurityError:
            ready = False
        selected.append(
            {
                "user": user,
                "ready": ready,
                "destination": "ending " + enrollment.phone[-4:] if enrollment else "Not enrolled",
            }
        )
        evidence.append(
            [user, raw.mobile_no, str(raw.modified), str(enrollment.modified) if enrollment else None, ready]
        )
    token = digest(secret(), "coverage-migration", frappe.local.site, str(config.modified), evidence)
    return {"version": 1, "users": selected, "review_token": token}


def apply_review(review_token):
    frappe.db.get_singles_dict("Login Security Settings", for_update=True)
    report = preview(lock=True)
    if report["version"] == 2:
        return {"status": "complete", "migrated_users": 0}
    import hmac

    if not isinstance(review_token, str) or not hmac.compare_digest(review_token, report["review_token"]):
        raise LoginSecurityError("changed", "Coverage or number details changed. Review the migration again.")
    if any(not row["ready"] for row in report["users"]):
        raise LoginSecurityError(
            "enrollment", "Reconcile and verify every selected User's Mobile No. before migrating."
        )
    # One database transaction; keep legacy selectors until the version marker is committed last.
    for row in report["users"]:
        frappe.db.set_value("User", row["user"], "login_security_enabled", 1)
    frappe.db.set_single_value(
        "Login Security Settings", "coverage_migration_snapshot", json.dumps(report["users"])
    )
    frappe.db.set_single_value("Login Security Settings", "coverage_version", 2)
    return {"status": "complete", "migrated_users": len(report["users"])}


def migrate_empty_policy():
    report = preview()
    if report["version"] == 1 and not report["users"]:
        apply_review(report["review_token"])


@frappe.whitelist(methods=["GET"])
def review():
    from login_security.enrollment import require_operator

    require_operator()
    return preview()


@frappe.whitelist(methods=["POST"])
@endpoint
def apply(review_token=None, password=None):
    from login_security.enrollment import require_operator
    from login_security.runtime import store

    actor = require_operator()
    store().rate("migration_operator", actor, 5, 3600)
    require_operator(password or "")
    # Serialize competing migration applications. User state is re-reviewed within the transaction.
    frappe.db.get_singles_dict("Login Security Settings", for_update=True)
    return apply_review(review_token)
