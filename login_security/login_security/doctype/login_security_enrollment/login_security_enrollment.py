from frappe.model.document import Document


class LoginSecurityEnrollment(Document):
    def validate(self):
        import frappe

        from login_security.enrollment import _WRITE_TOKEN

        if self.flags.get("login_security_write") is not _WRITE_TOKEN:
            raise frappe.PermissionError("Use the verified enrollment workflow.")
