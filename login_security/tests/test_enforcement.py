import unittest
from unittest.mock import patch

import frappe
from frappe.auth import LoginManager

from login_security.enforcement import authorize, require_verification


class EnforcementTests(unittest.TestCase):
    def setUp(self):
        frappe.local.flags = frappe._dict()
        frappe.local.login_security_proof = None
        self.manager = object.__new__(LoginManager)
        self.manager.user = "test@example.test"

    @patch("login_security.enforcement.covered", return_value=True)
    def test_real_post_login_guard_runs_before_session(self, covered):
        with (
            patch.object(
                LoginManager, "run_trigger", side_effect=lambda event: require_verification(self.manager)
            ),
            patch.object(LoginManager, "make_session") as session,
        ):
            with self.assertRaises(frappe.AuthenticationError):
                self.manager.post_login()
            session.assert_not_called()

    @patch("login_security.enforcement.covered", return_value=True)
    def test_client_boolean_or_other_user_is_not_proof(self, covered):
        for value in (True, (True, self.manager.user), {"otp_verified": True}):
            frappe.local.login_security_proof = value
            with self.assertRaises(frappe.AuthenticationError):
                require_verification(self.manager)
        authorize("someone-else@example.test")
        with self.assertRaises(frappe.AuthenticationError):
            require_verification(self.manager)

    @patch("login_security.enforcement.covered", return_value=True)
    def test_internal_bound_proof_is_accepted(self, covered):
        authorize(self.manager.user)
        require_verification(self.manager)

    @patch("login_security.enforcement.covered", return_value=False)
    def test_disabled_policy_preserves_native_login(self, covered):
        require_verification(self.manager)
