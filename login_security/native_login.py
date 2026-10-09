"""Version-specific adapter; core files are never edited.

Native login orchestration remains intact. A scoped password-expiry boundary
intercepts covered users before Frappe's native 2FA/session steps.
"""
import functools

import frappe
from frappe.auth import LoginManager


class PendingVerification(Exception):
    pass


def install():
    if getattr(LoginManager.login, "_login_security_adapter", False):
        return
    original_login = LoginManager.login
    original_expiry = LoginManager.force_user_to_reset_password

    @functools.wraps(original_expiry)
    def expiry(manager):
        expired = original_expiry(manager)
        if expired or getattr(frappe.local, "login_security_native_manager", None) is not manager:
            return expired
        # Prevent recursion when challenge account checks call the same method.
        frappe.local.login_security_native_manager = None
        from login_security import policy
        if "login_security" not in frappe.get_installed_apps():
            return expired
        config = policy.settings()
        if not policy.covered(manager.user, config):
            return expired
        from login_security.api.login import begin_challenge
        from login_security.runtime import check_request
        check_request()
        try:
            result = begin_challenge(manager, config)
        except Exception as error:
            from login_security.runtime import LoginSecurityError
            if isinstance(error, LoginSecurityError):
                raise
            if isinstance(error, frappe.AuthenticationError):
                raise LoginSecurityError("authentication", "Unable to authenticate.") from None
            raise LoginSecurityError("unavailable", "Login verification is unavailable. Try again later.") from None
        frappe.local.response["login_security"] = result
        raise PendingVerification

    @functools.wraps(original_login)
    def login(manager):
        from login_security.runtime import LoginSecurityError
        previous = getattr(frappe.local, "login_security_native_manager", None)
        frappe.local.login_security_native_manager = manager
        try:
            return original_login(manager)
        except PendingVerification:
            return False
        except LoginSecurityError as error:
            frappe.local.response["login_security"] = {
                "status": "error", "code": error.code, "message": error.message
            }
            return False
        finally:
            frappe.local.login_security_native_manager = previous
            frappe.form_dict.pop("pwd", None)

    login._login_security_adapter = True
    LoginManager.force_user_to_reset_password = expiry
    LoginManager.login = login
