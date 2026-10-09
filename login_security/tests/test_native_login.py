import unittest
from unittest.mock import patch, Mock
from contextlib import ExitStack

import frappe
from frappe.auth import LoginManager
from login_security.native_login import install


class NativeLoginTests(unittest.TestCase):
    def setUp(self):
        self.saved = {}
        for key, value in {
            "form_dict": frappe._dict(usr="alias", pwd="test-only"),
            "response": frappe._dict(),
            "login_security_native_manager": None,
            "db": Mock(get_single_value=Mock(return_value=0)),
        }.items():
            self.saved[key] = getattr(frappe.local, key, None)
            setattr(frappe.local, key, value)
        self.manager = object.__new__(LoginManager)
        self.manager.user = "staff@example.test"
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.stack.enter_context(patch("frappe.get_system_settings", return_value=0))
        self.stack.enter_context(patch("frappe.clear_cache"))
        self.stack.enter_context(patch("frappe.auth.get_cached_user_pass", return_value=(None, None)))
        self.stack.enter_context(patch.object(LoginManager, "authenticate"))
        self.stack.enter_context(patch("frappe.get_installed_apps", return_value=["frappe", "login_security"]))
        self.stack.enter_context(patch("login_security.policy.settings", return_value=frappe._dict(enabled=1)))
        self.stack.enter_context(patch("frappe.auth.should_run_2fa", return_value=False))

    def tearDown(self):
        for key,value in self.saved.items():
            setattr(frappe.local,key,value)

    def test_install_is_idempotent(self):
        before = LoginManager.login
        install()
        self.assertIs(LoginManager.login,before)

    def test_uncovered_user_completes_native_post_login(self):
        # Avoid DB-backed expiry policy in the original expiry function.
        with patch("login_security.policy.covered", return_value=False), patch.object(LoginManager, "post_login") as finish:
            self.manager.login()
            finish.assert_called_once()
        self.assertNotIn("pwd", frappe.form_dict)

    def test_covered_user_returns_challenge_without_session(self):
        with (
            patch("login_security.policy.covered", return_value=True),
            patch("login_security.runtime.check_request"),
            patch("login_security.api.login.begin_challenge", return_value={"status":"challenge"}) as challenge,
            patch.object(LoginManager, "post_login") as finish,
        ):
            self.assertIs(self.manager.login(),False)
            finish.assert_not_called()
            challenge.assert_called_once()
            self.assertEqual(frappe.local.response.login_security["status"],"challenge")
        self.assertNotIn("pwd",frappe.form_dict)
