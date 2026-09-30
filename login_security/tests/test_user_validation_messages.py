"""Activation errors identify the corrective action without live site changes."""

import unittest
from contextlib import ExitStack
from unittest.mock import Mock, patch

import frappe

from login_security.runtime import LoginSecurityError
from login_security.user_policy import validate_user


class UserValidationMessageTests(unittest.TestCase):
    def setUp(self):
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.previous = frappe._dict(login_security_enabled=0, mobile_no="+14155552671", enabled=1)
        self.doc = Mock(name="staff-document")
        self.doc.name = "staff@example.test"
        self.doc.user_type = "System User"
        self.doc.mobile_no = self.previous.mobile_no
        self.doc.enabled = 1
        self.doc.get.return_value = 1
        self.doc.get_doc_before_save.return_value = self.previous
        self.doc.is_new.return_value = False
        self.stack.enter_context(patch("login_security.user_policy.is_operator", return_value=True))
        self.stack.enter_context(
            patch("login_security.policy.settings", return_value=frappe._dict(coverage_version=2))
        )
        self.enrollment = self.stack.enter_context(
            patch("login_security.policy.enrollment", return_value=frappe._dict(phone=self.doc.mobile_no))
        )
        self.provider = self.stack.enter_context(patch("login_security.providers.validate_provider"))
        self.stack.enter_context(patch("frappe.twofactor.should_run_2fa", return_value=False))
        self.stack.enter_context(
            patch("frappe.throw", side_effect=lambda message, *args: self.fail_validation(message))
        )

    @staticmethod
    def fail_validation(message):
        raise frappe.ValidationError(message)

    def test_invalid_number_explains_format_before_enrollment(self):
        self.doc.mobile_no = self.previous.mobile_no = "4155552671"
        with self.assertRaisesRegex(frappe.ValidationError, "international format"):
            validate_user(self.doc)
        self.enrollment.assert_not_called()
        self.provider.assert_not_called()

    def test_unverified_number_explains_verify_action(self):
        self.enrollment.side_effect = LoginSecurityError("enrollment", "Not enrolled")
        with self.assertRaisesRegex(frappe.ValidationError, "Login Security > Verify Mobile No."):
            validate_user(self.doc)
        self.provider.assert_not_called()

    def test_sender_error_is_distinct_and_does_not_expose_exception(self):
        self.provider.side_effect = ValueError("private provider details")
        with self.assertRaisesRegex(frappe.ValidationError, "Open Login Security Settings") as caught:
            validate_user(self.doc)
        self.assertNotIn("private provider details", str(caught.exception))

    def test_verified_number_and_valid_sender_pass(self):
        validate_user(self.doc)
        self.provider.assert_called_once()
