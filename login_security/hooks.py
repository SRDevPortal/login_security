from pathlib import Path as _Path

app_name = "login_security"
app_title = "Login Security"
app_publisher = "Login Security Contributors"
app_description = "Staff login verification with replaceable delivery channels"
app_email = ""
app_license = "mit"
# Resolve the sibling app locally: Frappe v15 looks up bare custom names on GitHub.
required_apps = ["frappe", str(_Path(__file__).resolve().parents[2] / "wa_chat_hub")]

web_include_js = ["/assets/login_security/js/login.js?v=20260929-4"]
on_login = "login_security.enforcement.require_verification"
on_session_creation = "login_security.enforcement.mark_session"
after_request = "login_security.runtime.no_store_response"
after_install = "login_security.install.after_install"
after_migrate = "login_security.install.after_migrate"
doctype_js = {"User": "public/js/user.js"}
doc_events = {
    "User": {
        "validate": "login_security.user_policy.validate_user",
        "on_update": "login_security.user_policy.audit_user_change",
    }
}
scheduler_events = {"daily": ["login_security.audit.remove_expired_events"]}

# Authenticate first, then protect raw verified-phone enrollment HTTP reads.
auth_hooks = ["login_security.document_privacy.guard_request"]
