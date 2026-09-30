import frappe


def after_install():
    # Installation never opts a site into enforcement or changes native 2FA.
    settings = frappe.get_single("Login Security Settings")
    settings.enabled = 0
    settings.save(ignore_permissions=True)
    after_migrate()


def ensure_user_fields():
    from frappe.custom.doctype.custom_field.custom_field import create_custom_fields

    create_custom_fields(
        {
            "User": [
                {
                    "fieldname": "login_security_section",
                    "fieldtype": "Section Break",
                    "label": "Login Security",
                    "insert_after": "mobile_no",
                    "module": "Login Security",
                },
                {
                    "fieldname": "login_security_enabled",
                    "fieldtype": "Check",
                    "label": "Enable Login Verification",
                    "default": "0",
                    "permlevel": 1,
                    "insert_after": "login_security_section",
                    "module": "Login Security",
                    "description": "Ask for a WhatsApp code after the password. The site service must be active.",
                },
                {
                    "fieldname": "login_security_status",
                    "fieldtype": "HTML",
                    "label": "Verification Status",
                    "insert_after": "login_security_enabled",
                    "module": "Login Security",
                },
                {
                    "fieldname": "login_security_end",
                    "fieldtype": "Section Break",
                    "insert_after": "login_security_status",
                    "module": "Login Security",
                },
            ]
        }
    )


def after_migrate():
    ensure_user_fields()
    from login_security.coverage_migration import migrate_empty_policy

    migrate_empty_policy()


def sync_revision():
    """Sync this app only on an existing site; regular bench migrate also works."""
    from frappe.model.sync import sync_for

    sync_for("login_security", force=True)
    after_migrate()
    frappe.clear_cache()
