"""Customer-number privacy capability checks for Login Security."""
from __future__ import annotations

import frappe


def enabled() -> bool:
    return bool(frappe.conf.get("privacy_shield_desk_enabled", False)) and (
        "privacy_shield" in frappe.get_installed_apps()
    )


def restricted(user=None) -> bool:
    if not enabled():
        return False
    from privacy_shield.policy import current_capabilities

    return not current_capabilities(user).view_full
