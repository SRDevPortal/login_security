"""Read-only inventory; deliberately excludes credentials and phone numbers."""

import frappe


def inventory():
    return {
        "site": frappe.local.site,
        "frappe_version": frappe.__version__,
        "login_security_installed": "login_security" in frappe.get_installed_apps(),
        "login_security_enabled": bool(frappe.db.get_single_value("Login Security Settings", "enabled"))
        if "login_security" in frappe.get_installed_apps()
        else False,
        "wa_chat_hub_installed": "wa_chat_hub" in frappe.get_installed_apps(),
        "native_2fa_enabled": bool(frappe.get_system_settings("enable_two_factor_auth")),
        "password_login_disabled": bool(frappe.get_system_settings("disable_user_pass_login")),
        "email_link_login_enabled": bool(frappe.get_system_settings("login_with_email_link")),
        "enabled_social_providers": frappe.db.count("Social Login Key", {"enable_social_login": 1}),
        "enabled_staff_count": frappe.db.count("User", {"enabled": 1, "user_type": "System User"}),
        "redis_available": bool(frappe.cache.ping()),
        "coverage_version": int(
            frappe.db.get_single_value("Login Security Settings", "coverage_version") or 0
        ),
        "user_custom_fields": frappe.db.count("Custom Field", {"dt": "User", "module": "Login Security"}),
        "users_with_verification_enabled": frappe.db.count("User", {"login_security_enabled": 1})
        if frappe.get_meta("User").has_field("login_security_enabled")
        else 0,
    }


if __name__ == "__main__":
    import json
    import os
    import sys

    frappe.init(site=sys.argv[1], sites_path=os.path.join(os.getcwd(), "sites"))
    try:
        frappe.connect()
        print(json.dumps(inventory(), indent=2))
    finally:
        frappe.destroy()
