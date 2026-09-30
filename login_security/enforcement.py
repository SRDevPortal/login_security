import frappe

from login_security.policy import covered

_PROOF = object()


def authorize(user):
    frappe.local.login_security_proof = (_PROOF, user)


def has_proof(user):
    value = getattr(frappe.local, "login_security_proof", None)
    return isinstance(value, tuple) and len(value) == 2 and value[0] is _PROOF and value[1] == user


def require_verification(login_manager):
    if covered(login_manager.user) and not has_proof(login_manager.user):
        frappe.flags.disable_traceback = True
        raise frappe.AuthenticationError("Complete login verification on the login page.")


def mark_session(login_manager):
    if has_proof(login_manager.user):
        frappe.session.data.login_security_verified = True
        frappe.local.session_obj.update(force=True)
        frappe.local.login_security_proof = None
