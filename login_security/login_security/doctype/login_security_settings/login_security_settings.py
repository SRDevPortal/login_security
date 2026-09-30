from frappe.model.document import Document


class LoginSecuritySettings(Document):
    def validate(self):
        from login_security.policy import validate_settings

        validate_settings(self)
