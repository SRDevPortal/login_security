import inspect
import unittest
from unittest.mock import Mock, patch

import frappe

from login_security.api import login
from login_security.runtime import LoginSecurityError


class LoginStartTests(unittest.TestCase):
    def setUp(self):
        self.old_session = getattr(frappe.local, "session", None)
        self.old_manager = getattr(frappe.local, "login_manager", None)
        self.old_ip = getattr(frappe.local, "request_ip", None)
        frappe.local.session = frappe._dict(user="Guest")
        frappe.local.request_ip = "192.0.2.1"
        self.manager = Mock(user="resolved@example.test")
        frappe.local.login_manager = self.manager

    def tearDown(self):
        frappe.local.session = self.old_session
        frappe.local.login_manager = self.old_manager
        frappe.local.request_ip = self.old_ip

    def test_uncovered_user_does_not_need_challenge_origin_or_issue_session(self):
        with (
            patch.object(login.policy, "settings", return_value=frappe._dict(enabled=1)),
            patch.object(login.policy, "covered", return_value=False) as covered,
            patch.object(login, "store", return_value=Mock()),
            patch.object(login, "check_request") as origin,
            patch.object(login, "deliver") as delivery,
        ):
            result = inspect.unwrap(login.start)("alias", "password")
            self.assertEqual(result, {"status": "native_login"})
            self.manager.authenticate.assert_called_once_with(user="alias", pwd="password")
            covered.assert_called_once_with(self.manager.user, unittest.mock.ANY)
            origin.assert_not_called()
            delivery.assert_not_called()
            self.manager.post_login.assert_not_called()

    def test_covered_user_origin_failure_prevents_delivery_and_session(self):
        with (
            patch.object(login.policy, "settings", return_value=frappe._dict(enabled=1)),
            patch.object(login.policy, "covered", return_value=True),
            patch.object(login, "store", return_value=Mock()),
            patch.object(login, "check_request", side_effect=LoginSecurityError("origin", "Rejected")),
            patch.object(login.policy, "enrollment") as enrollment,
            patch.object(login, "deliver") as delivery,
        ):
            with self.assertRaises(LoginSecurityError):
                inspect.unwrap(login.start)("alias", "password")
            enrollment.assert_not_called()
            delivery.assert_not_called()
            self.manager.post_login.assert_not_called()

    def test_wrong_password_never_sends_code(self):
        self.manager.authenticate.side_effect = frappe.AuthenticationError
        with (
            patch.object(login.policy, "settings", return_value=frappe._dict(enabled=1)),
            patch.object(login, "store", return_value=Mock()),
            patch.object(login, "deliver") as delivery,
        ):
            with self.assertRaises(frappe.AuthenticationError):
                inspect.unwrap(login.start)("alias", "incorrect")
            delivery.assert_not_called()
            self.manager.post_login.assert_not_called()


    def test_real_challenge_function_initializes_storage_and_secure_cookie(self):
        storage = Mock()
        storage.create.return_value = ("opaque-challenge", {"user": self.manager.user})
        config = frappe._dict(code_ttl=300, max_attempts=5, send_limit=10)
        cookie_manager = Mock()
        previous_cookie_manager = getattr(frappe.local, "cookie_manager", None)
        frappe.local.cookie_manager = cookie_manager
        try:
            with (
                patch.object(login, "store", return_value=storage),
                patch.object(login.policy, "account_checks"),
                patch.object(login.policy, "enrollment", return_value=frappe._dict(phone="+14155552671")),
                patch.object(login.policy, "fingerprint", return_value="opaque-fingerprint"),
                patch.object(login.providers, "validate_provider"),
                patch.object(login, "request_scheme", return_value="https"),
                patch.object(login.audit, "record"),
                patch.object(login, "deliver", return_value={"status": "challenge"}) as deliver,
            ):
                result = login.begin_challenge(self.manager, config)
                self.assertEqual(result["status"], "challenge")
                storage.create.assert_called_once()
                self.assertTrue(cookie_manager.set_cookie.call_args.kwargs["secure"])
                deliver.assert_called_once()
                self.manager.post_login.assert_not_called()
        finally:
            frappe.local.cookie_manager = previous_cookie_manager
