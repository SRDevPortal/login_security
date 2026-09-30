import frappe
from frappe.utils import add_days, now_datetime


def record(user, event, outcome, reference=None):
    # Only fixed event/outcome codes and opaque references belong here.
    frappe.get_doc(
        {
            "doctype": "Login Security Event",
            "user": user,
            "event_type": event,
            "outcome": outcome,
            "challenge_reference": reference,
        }
    ).insert(ignore_permissions=True)


def remove_expired_events():
    days = frappe.db.get_single_value("Login Security Settings", "audit_retention_days") or 30
    frappe.db.delete("Login Security Event", {"creation": ("<", add_days(now_datetime(), -int(days)))})
