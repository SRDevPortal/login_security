"""Opt-in real Frappe WSGI tests; temporary principals, mocked delivery, no policy writes.

LOGIN_SECURITY_TEST_SITE=site1.local python -m unittest ...
Run only on a development/staging site with Login Security installed.
"""

import json
import os
import secrets
import unittest
from unittest.mock import patch

import frappe
from frappe.app import application
from werkzeug.test import Client
from werkzeug.wrappers import Response

from login_security.crypto import digest
from login_security.enrollment import _WRITE_TOKEN, recovery_digest
from login_security.runtime import store

SITE = os.environ.get("LOGIN_SECURITY_TEST_SITE")
BENCH = os.path.abspath(os.environ.get("LOGIN_SECURITY_TEST_BENCH", os.getcwd()))


@unittest.skipUnless(SITE, "Set LOGIN_SECURITY_TEST_SITE to run real-site integration tests")
class SiteIntegrationTests(unittest.TestCase):
    @classmethod
    def connect(cls):
        frappe.init(site=SITE, sites_path=os.path.join(BENCH, "sites"))
        frappe.connect()
        frappe.set_user("Administrator")

    @classmethod
    def setUpClass(cls):
        cls.original_cwd = os.getcwd()
        os.chdir(os.path.join(BENCH, "sites"))
        cls.connect()
        if "login_security" not in frappe.get_installed_apps():
            raise unittest.SkipTest("Install login_security on the development site first")
        actual = frappe.get_single("Login Security Settings")
        if actual.enabled or frappe.get_system_settings("enable_two_factor_auth"):
            raise unittest.SkipTest("Tests require disabled live enforcement and native 2FA")
        cls.user = "login-security-test-" + secrets.token_hex(6) + "@example.invalid"
        cls.password = secrets.token_urlsafe(32)
        cls.phone = "+1415555" + str(secrets.randbelow(10000)).zfill(4)
        frappe.get_doc(
            {
                "doctype": "User",
                "email": cls.user,
                "first_name": "Login Security Test",
                "enabled": 1,
                "mobile_no": cls.phone,
                "send_welcome_email": 0,
                "new_password": cls.password,
                "roles": [{"role": "System Manager"}],
            }
        ).insert()
        cls.recovery = secrets.token_hex(16)
        enrollment = frappe.get_doc(
            {
                "doctype": "Login Security Enrollment",
                "user": cls.user,
                "phone": cls.phone,
                "verified_at": frappe.utils.now_datetime(),
                "enabled": 1,
                "verified_by": "Administrator",
                "recovery_hashes": json.dumps([recovery_digest(cls.user, cls.recovery)]),
            }
        )
        enrollment.flags.login_security_write = _WRITE_TOKEN
        enrollment.insert(ignore_permissions=True)
        cls.config = actual
        cls.config.enabled = 1
        cls.config.coverage_version = 2
        cls.config.users = [frappe._dict(user=cls.user)]
        cls.config.roles = []
        cls.config.all_staff = 0
        cls.config.send_limit = 30
        with (
            patch("login_security.policy.settings", return_value=cls.config),
            patch("login_security.providers.validate_provider"),
        ):
            user_doc = frappe.get_doc("User", cls.user)
            user_doc.login_security_enabled = 1
            user_doc.save()
        frappe.db.commit()
        frappe.destroy()

    @classmethod
    def tearDownClass(cls):
        cls.connect()
        try:
            # Remove only this run's explicitly-created principal and its artifacts.
            from frappe.sessions import clear_sessions

            clear_sessions(cls.user, force=True)
            frappe.db.delete("Login Security Event", {"user": cls.user})
            frappe.delete_doc("Login Security Enrollment", cls.user, force=True, ignore_permissions=True)
            frappe.delete_doc("User", cls.user, force=True, ignore_permissions=True)
            frappe.db.commit()
        finally:
            frappe.destroy()
            os.chdir(cls.original_cwd)

    def setUp(self):
        self.connect()
        storage = store()
        # Reset only counters keyed to this run's temporary user/number, never shared IP budgets.
        for category, identity in (
            ("start_identifier", self.user),
            ("send_user", self.user),
            ("send_phone", self.phone),
            ("verify_user", self.user),
            ("recovery_user", self.user),
        ):
            storage.client.delete(storage.prefix + "rate:" + digest(storage.secret, category, identity))
        frappe.destroy()
        self.test_ip = "192.0.2." + str(secrets.randbelow(250) + 1)
        self.client = Client(application, Response)
        self.code = None
        self.config_patch = patch("login_security.policy.settings", return_value=self.config)
        self.validation_patch = patch("login_security.providers.validate_provider")
        self.send_patch = patch("login_security.providers.send", side_effect=self.capture_code)
        self.config_patch.start()
        self.validation_patch.start()
        self.sender = self.send_patch.start()

    def tearDown(self):
        self.send_patch.stop()
        self.validation_patch.stop()
        self.config_patch.stop()

    def capture_code(self, config, phone, code, reference):
        self.code = code
        return {"outcome": "accepted", "message_id": "test-only"}

    def post(self, method, data, client=None, origin=True):
        headers = {"X-Frappe-Site-Name": SITE, "X-Login-Security": "1", "X-Forwarded-For": self.test_ip}
        if origin:
            headers["Origin"] = "https://" + SITE
        return (client or self.client).post(
            "/api/method/" + method, json=data, base_url="https://" + SITE, headers=headers
        )

    def start(self):
        response = self.post("login_security.api.login.start", {"usr": self.user, "pwd": self.password})
        self.assertEqual(response.status_code, 200)
        result = response.get_json()["message"]
        self.assertEqual(result["status"], "challenge", result)
        return result

    def test_01_password_then_otp_real_session(self):
        challenge = self.start()
        cookies = " ".join(
            self.client.get_cookie(name, domain=SITE).value
            for name in ("sid",)
            if self.client.get_cookie(name, domain=SITE)
        )
        self.assertIn(cookies, ("", "Guest"))
        response = self.post(
            "login_security.api.login.verify", {"challenge_id": challenge["challenge_id"], "code": self.code}
        )
        result = response.get_json()["message"]
        self.assertEqual(result["status"], "logged_in", result)
        cookie = self.client.get_cookie("sid", domain=SITE)
        self.assertIsNotNone(cookie)
        self.assertNotEqual(cookie.value, "Guest")
        self.assertIn("no-store", response.headers["Cache-Control"])

    def test_02_direct_native_login_cannot_issue_session(self):
        response = self.post("login", {"usr": self.user, "pwd": self.password})
        self.assertEqual(response.status_code, 401)
        cookie = self.client.get_cookie("sid", domain=SITE)
        self.assertTrue(cookie is None or cookie.value in ("", "Guest"))

    def test_03_invalid_password_does_not_send(self):
        response = self.post("login_security.api.login.start", {"usr": self.user, "pwd": "incorrect"})
        self.assertEqual(response.get_json()["message"]["status"], "error")
        self.sender.assert_not_called()

    def test_04_foreign_browser_and_wrong_code(self):
        challenge = self.start()
        other = Client(application, Response)
        payload = {"challenge_id": challenge["challenge_id"], "code": self.code}
        result = self.post("login_security.api.login.verify", payload, client=other).get_json()["message"]
        self.assertEqual(result["status"], "error")
        payload["code"] = "invalid"
        result = self.post("login_security.api.login.verify", payload).get_json()["message"]
        self.assertEqual(result["status"], "error")

    def test_05_recovery_code_consumed(self):
        challenge = self.start()
        result = self.post(
            "login_security.api.login.recover",
            {"challenge_id": challenge["challenge_id"], "recovery_code": self.recovery},
        ).get_json()["message"]
        self.assertEqual(result["status"], "logged_in", result)
        self.client = Client(application, Response)
        challenge = self.start()
        result = self.post(
            "login_security.api.login.recover",
            {"challenge_id": challenge["challenge_id"], "recovery_code": self.recovery},
        ).get_json()["message"]
        self.assertEqual(result["status"], "error")

    def test_06_cross_origin_start_rejected(self):
        result = self.post(
            "login_security.api.login.start", {"usr": self.user, "pwd": self.password}, origin=False
        ).get_json()["message"]
        self.assertEqual(result["status"], "error")
        self.sender.assert_not_called()

    def test_07_login_page_contains_custom_asset(self):
        response = self.client.get(
            "/login?redirect-to=/crm", base_url="https://" + SITE, headers={"X-Frappe-Site-Name": SITE}
        )
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"/assets/login_security/js/login.js", response.data)
        self.assertIn(b"login_email", response.data)

    def test_08_native_factor_is_not_bypassed(self):
        with patch("login_security.policy.should_run_2fa", return_value=True):
            result = self.post(
                "login_security.api.login.start", {"usr": self.user, "pwd": self.password}
            ).get_json()["message"]
        self.assertEqual(result["code"], "native_2fa")
        self.sender.assert_not_called()

    def test_09_disabled_user_mid_challenge(self):
        challenge = self.start()
        self.connect()
        frappe.db.set_value("User", self.user, "enabled", 0)
        frappe.db.commit()
        frappe.destroy()
        try:
            result = self.post(
                "login_security.api.login.verify",
                {"challenge_id": challenge["challenge_id"], "code": self.code},
            ).get_json()["message"]
            self.assertEqual(result["status"], "error")
        finally:
            self.connect()
            frappe.db.set_value("User", self.user, "enabled", 1)
            frappe.db.commit()
            frappe.destroy()

    def test_10_password_change_invalidates_challenge(self):
        challenge = self.start()
        self.connect()
        from frappe.utils.password import update_password

        # Even resetting to the same password creates a new salted hash/version.
        update_password(self.user, self.password)
        frappe.db.commit()
        frappe.destroy()
        result = self.post(
            "login_security.api.login.verify", {"challenge_id": challenge["challenge_id"], "code": self.code}
        ).get_json()["message"]
        self.assertEqual(result["code"], "changed")

    def test_11_email_link_cannot_create_covered_session(self):
        self.connect()
        key = secrets.token_urlsafe(32)
        frappe.cache.set_value("one_time_login_key:" + key, self.user, expires_in_sec=60)
        frappe.destroy()
        try:
            response = self.client.get(
                "/api/method/frappe.www.login.login_via_key",
                query_string={"key": key},
                base_url="https://" + SITE,
                headers={"X-Frappe-Site-Name": SITE, "X-Forwarded-For": self.test_ip},
            )
            self.assertEqual(response.status_code, 401)
            cookie = self.client.get_cookie("sid", domain=SITE)
            self.assertTrue(cookie is None or cookie.value in ("", "Guest"))
        finally:
            self.connect()
            frappe.cache.delete_value("one_time_login_key:" + key)
            frappe.destroy()

    def test_12_provider_timeout_does_not_create_session(self):
        self.sender.side_effect = lambda *args: {"outcome": "unknown"}
        result = self.start()
        self.assertEqual(result["delivery"], "unknown")
        cookie = self.client.get_cookie("sid", domain=SITE)
        self.assertTrue(cookie is None or cookie.value in ("", "Guest"))

    def test_13_enrollment_cannot_be_forged_by_document_update(self):
        self.connect()
        try:
            doc = frappe.get_doc("Login Security Enrollment", self.user)
            doc.phone = "+14155552671"
            with self.assertRaises(frappe.PermissionError):
                doc.save(ignore_permissions=True)
            frappe.db.rollback()
        finally:
            frappe.destroy()

    def test_14_number_version_change_invalidates_challenge(self):
        challenge = self.start()
        self.connect()
        frappe.db.set_value(
            "Login Security Enrollment", self.user, "verified_at", frappe.utils.now_datetime()
        )
        frappe.db.commit()
        frappe.destroy()
        result = self.post(
            "login_security.api.login.verify", {"challenge_id": challenge["challenge_id"], "code": self.code}
        ).get_json()["message"]
        self.assertEqual(result["code"], "changed")

    def test_15_http_rejected_without_developer_exception(self):
        response = self.client.post(
            "/api/method/login_security.api.login.start",
            base_url="http://insecure.example",
            json={"usr": self.user, "pwd": self.password},
            headers={
                "X-Frappe-Site-Name": SITE,
                "X-Login-Security": "1",
                "Origin": "http://insecure.example",
            },
        )
        self.assertEqual(response.get_json()["message"]["code"], "https")
        self.sender.assert_not_called()

    def test_16_admin_assisted_enrollment_and_one_time_display(self):
        challenge = self.start()
        result = self.post(
            "login_security.api.login.verify", {"challenge_id": challenge["challenge_id"], "code": self.code}
        ).get_json()["message"]
        self.assertEqual(result["status"], "logged_in")
        cookie = self.client.get_cookie("sid", domain=SITE)
        self.connect()
        session = frappe.cache.hget("session", cookie.value)
        csrf = session["data"].get("csrf_token")
        self.assertTrue(session["data"]["login_security_verified"])
        frappe.destroy()

        headers = {"X-Frappe-Site-Name": SITE, "X-Login-Security": "1", "Origin": "https://" + SITE}
        if csrf:
            headers["X-Frappe-CSRF-Token"] = csrf

        def call(method, data):
            return self.client.post(
                "/api/method/login_security.enrollment." + method,
                json=data,
                base_url="https://" + SITE,
                headers=headers,
            ).get_json()["message"]

        result = call("begin", {"user": self.user, "password": self.password})
        self.assertEqual(result["status"], "challenge", result)
        result = call("complete", {"challenge_id": result["challenge_id"], "code": self.code})
        self.assertEqual(result["status"], "enrolled", result)
        self.assertEqual(len(set(result["recovery_codes"])), 10)
        self.connect()
        hashes = frappe.db.get_value("Login Security Enrollment", self.user, "recovery_hashes")
        self.assertNotIn(result["recovery_codes"][0], hashes)
        frappe.destroy()

    def operator_call(self, method, data):
        """Reuse the real OTP login and its CSRF token for protected enrollment APIs."""
        cookie = self.client.get_cookie("sid", domain=SITE)
        if not cookie or cookie.value == "Guest":
            challenge = self.start()
            result = self.post(
                "login_security.api.login.verify",
                {
                    "challenge_id": challenge["challenge_id"],
                    "code": self.code,
                },
            ).get_json()["message"]
            self.assertEqual(result["status"], "logged_in")
            cookie = self.client.get_cookie("sid", domain=SITE)
        self.connect()
        session = frappe.cache.hget("session", cookie.value)
        csrf = session["data"].get("csrf_token")
        frappe.destroy()
        headers = {"X-Frappe-Site-Name": SITE, "X-Login-Security": "1", "Origin": "https://" + SITE}
        if csrf:
            headers["X-Frappe-CSRF-Token"] = csrf
        return self.client.post(
            "/api/method/login_security.enrollment." + method,
            json=data,
            base_url="https://" + SITE,
            headers=headers,
        ).get_json()["message"]

    def test_17_checkbox_controls_coverage_and_invalidates_old_challenge(self):
        from login_security import policy

        challenge = self.start()
        code = self.code
        self.connect()
        try:
            user = frappe.get_doc("User", self.user)
            user.login_security_enabled = 0
            user.save()
            self.assertFalse(policy.covered(self.user))
            user.login_security_enabled = 1
            user.save()
            self.assertTrue(policy.covered(self.user))
            frappe.db.commit()
        finally:
            frappe.destroy()
        result = self.post(
            "login_security.api.login.verify",
            {
                "challenge_id": challenge["challenge_id"],
                "code": code,
            },
        ).get_json()["message"]
        self.assertEqual(result["code"], "changed")

    def test_18_number_mismatch_fails_closed(self):
        self.connect()
        frappe.db.set_value("User", self.user, "mobile_no", "+14155552671")
        frappe.db.commit()
        frappe.destroy()
        try:
            result = self.post(
                "login_security.api.login.start", {"usr": self.user, "pwd": self.password}
            ).get_json()["message"]
            self.assertEqual(result["code"], "enrollment")
            self.sender.assert_not_called()
        finally:
            self.connect()
            frappe.db.set_value("User", self.user, "mobile_no", self.phone)
            frappe.db.commit()
            frappe.destroy()

    def test_19_document_edits_cannot_redirect_number_or_self_disable(self):
        self.connect()
        try:
            user = frappe.get_doc("User", self.user)
            user.mobile_no = "+14155552671"
            with self.assertRaises(frappe.ValidationError):
                user.save(ignore_permissions=True)
            frappe.db.rollback()
            user = frappe.get_doc("User", self.user)
            user.login_security_enabled = 0
            with (
                patch("login_security.user_policy.is_operator", return_value=False),
                self.assertRaises(frappe.PermissionError),
            ):
                user.save(ignore_permissions=True)
            frappe.db.rollback()
            self.assertEqual(frappe.db.get_value("User", self.user, "mobile_no"), self.phone)
            self.assertEqual(frappe.db.get_value("User", self.user, "login_security_enabled"), 1)
        finally:
            frappe.destroy()

    def test_20_initial_enrollment_rejects_recipient_override(self):
        result = self.operator_call("begin", {"user": {}, "password": self.password})
        self.assertEqual(result["status"], "error")
        result = self.operator_call(
            "begin", {"user": self.user, "phone": "+14155552671", "password": self.password}
        )
        self.assertEqual(result["code"], "phone")
        sent_before = self.sender.call_count
        result = self.operator_call("begin", {"user": self.user, "password": self.password})
        self.assertEqual(result["status"], "challenge")
        self.assertEqual(self.sender.call_count, sent_before + 1)
        self.assertEqual(self.sender.call_args.args[1], self.phone)

    def test_21_replacement_is_staged_and_commits_only_after_correct_code(self):
        replacement = "+1415555" + str(secrets.randbelow(10000)).zfill(4)
        result = self.operator_call(
            "begin_change", {"user": self.user, "new_phone": replacement, "password": self.password}
        )
        self.assertEqual(result["status"], "challenge", result)
        code, challenge_id = self.code, result["challenge_id"]
        self.assertEqual(self.sender.call_args.args[1], replacement)
        self.connect()
        self.assertEqual(frappe.db.get_value("User", self.user, "mobile_no"), self.phone)
        old_hashes = frappe.db.get_value("Login Security Enrollment", self.user, "recovery_hashes")
        frappe.destroy()
        result = self.operator_call("complete", {"challenge_id": challenge_id, "code": "invalid"})
        self.assertEqual(result["status"], "error")
        result = self.operator_call("complete", {"challenge_id": challenge_id, "code": code})
        self.assertEqual(result["status"], "enrolled", result)
        self.connect()
        try:
            self.assertEqual(frappe.db.get_value("User", self.user, "mobile_no"), replacement)
            self.assertEqual(
                frappe.db.get_value("Login Security Enrollment", self.user, "phone"), replacement
            )
            self.assertNotEqual(
                frappe.db.get_value("Login Security Enrollment", self.user, "recovery_hashes"), old_hashes
            )
            self.assertEqual(frappe.db.get_value("User", self.user, "login_security_enabled"), 1)
        finally:
            # Test-only restoration. Production writes go through the protected workflow.
            frappe.db.set_value("User", self.user, "mobile_no", self.phone)
            frappe.db.set_value("Login Security Enrollment", self.user, "phone", self.phone)
            frappe.db.commit()
            frappe.destroy()

    def test_22_profile_change_invalidates_pending_replacement(self):
        result = self.operator_call(
            "begin_change", {"user": self.user, "new_phone": "+14155552671", "password": self.password}
        )
        self.assertEqual(result["status"], "challenge", result)
        code, challenge_id = self.code, result["challenge_id"]
        self.connect()
        frappe.db.set_value("User", self.user, "first_name", "Updated Test")
        frappe.db.commit()
        frappe.destroy()
        result = self.operator_call("complete", {"challenge_id": challenge_id, "code": code})
        self.assertEqual(result["code"], "changed")
        self.connect()
        self.assertEqual(frappe.db.get_value("User", self.user, "mobile_no"), self.phone)
        self.assertEqual(frappe.db.get_value("Login Security Enrollment", self.user, "phone"), self.phone)
        frappe.destroy()

    def test_23_custom_fields_are_app_owned_and_idempotent(self):
        self.connect()
        try:
            from login_security.install import ensure_user_fields

            ensure_user_fields()
            ensure_user_fields()
            fields = frappe.get_all(
                "Custom Field", filters={"dt": "User", "module": "Login Security"}, pluck="fieldname"
            )
            self.assertEqual(len(fields), 4)
            field = frappe.get_meta("User").get_field("login_security_enabled")
            self.assertEqual(field.permlevel, 1)
            self.assertEqual(field.label, "Enable Login Verification")
        finally:
            frappe.db.rollback()
            frappe.destroy()

    def test_24_legacy_migration_requires_ready_unchanged_review(self):
        from login_security import coverage_migration
        from login_security.runtime import LoginSecurityError

        self.connect()
        original_version = self.config.coverage_version
        try:
            self.config.coverage_version = 0
            self.config.enabled = 0
            report = coverage_migration.preview()
            self.assertEqual([row["user"] for row in report["users"]], [self.user])
            self.assertTrue(report["users"][0]["ready"])
            with self.assertRaises(LoginSecurityError):
                coverage_migration.apply_review("stale")
            frappe.db.set_value("User", self.user, "mobile_no", "+14155552671")
            unready = coverage_migration.preview()
            with self.assertRaises(LoginSecurityError):
                coverage_migration.apply_review(unready["review_token"])
            frappe.db.rollback()
            report = coverage_migration.preview()
            result = coverage_migration.apply_review(report["review_token"])
            self.assertEqual(result["migrated_users"], 1)
            self.assertEqual(
                int(frappe.db.get_single_value("Login Security Settings", "coverage_version")), 2
            )
            frappe.db.rollback()
        finally:
            self.config.coverage_version = original_version
            self.config.enabled = 1
            frappe.db.rollback()
            frappe.destroy()

    def test_25_failed_number_save_rolls_back_enrollment(self):
        result = self.operator_call(
            "begin_change",
            {
                "user": self.user,
                "new_phone": "+14155552671",
                "password": self.password,
            },
        )
        self.assertEqual(result["status"], "challenge", result)
        with patch("login_security.user_policy.validate_user", side_effect=frappe.PermissionError):
            result = self.operator_call(
                "complete", {"challenge_id": result["challenge_id"], "code": self.code}
            )
        self.assertEqual(result["status"], "error")
        self.connect()
        try:
            self.assertEqual(frappe.db.get_value("User", self.user, "mobile_no"), self.phone)
            self.assertEqual(frappe.db.get_value("Login Security Enrollment", self.user, "phone"), self.phone)
        finally:
            frappe.destroy()

    def test_26_flags_are_independent_and_roles_do_not_select_users(self):
        from login_security import policy

        self.connect()
        other = self.user.replace("@", "-other@")
        try:
            frappe.get_doc(
                {
                    "doctype": "User",
                    "email": other,
                    "first_name": "Other Test",
                    "enabled": 1,
                    "send_welcome_email": 0,
                    "mobile_no": "+14155552671",
                    "roles": [{"role": "System Manager"}],
                }
            ).insert()
            self.assertTrue(policy.covered(self.user))
            self.assertFalse(policy.covered(other))
            with patch("frappe.get_roles", return_value=[]):
                self.assertTrue(policy.covered(self.user))
            with patch("frappe.get_roles", return_value=["System Manager"]):
                self.assertFalse(policy.covered(other))
            # Trusted fixture establishes a second, different verified destination.
            enrollment = frappe.get_doc(
                {
                    "doctype": "Login Security Enrollment",
                    "user": other,
                    "phone": "+14155552671",
                    "enabled": 1,
                    "verified_at": frappe.utils.now_datetime(),
                    "verified_by": "Administrator",
                    "recovery_hashes": "[]",
                }
            )
            enrollment.flags.login_security_write = _WRITE_TOKEN
            enrollment.insert(ignore_permissions=True)
            other_doc = frappe.get_doc("User", other)
            other_doc.login_security_enabled = 1
            other_doc.save()
            self.assertTrue(policy.covered(other))
            self.assertEqual(policy.enrollment(other).phone, "+14155552671")
            self.assertEqual(policy.enrollment(self.user).phone, self.phone)
        finally:
            frappe.db.rollback()
            frappe.clear_cache(user=other)
            frappe.destroy()

    def test_27_enabling_requires_current_verified_number(self):
        self.connect()
        try:
            frappe.db.set_value("User", self.user, "login_security_enabled", 0)
            frappe.db.set_value("Login Security Enrollment", self.user, "enabled", 0)
            user = frappe.get_doc("User", self.user)
            user.login_security_enabled = 1
            with self.assertRaises(frappe.ValidationError):
                user.save()
        finally:
            frappe.db.rollback()
            frappe.destroy()

    def test_28_mobile_required_on_every_save_when_verification_enabled(self):
        self.connect()
        try:
            for previous_flag, mobile in ((0, ""), (1, ""), (1, "   ")):
                with self.subTest(previous_flag=previous_flag, mobile=repr(mobile)):
                    frappe.db.set_value(
                        "User",
                        self.user,
                        {
                            "login_security_enabled": previous_flag,
                            "mobile_no": mobile,
                        },
                    )
                    user = frappe.get_doc("User", self.user)
                    user.login_security_enabled = 1
                    with self.assertRaisesRegex(frappe.MandatoryError, "Mobile No. is required"):
                        user.save(ignore_permissions=True)
                    frappe.db.rollback()
        finally:
            frappe.db.rollback()
            frappe.destroy()
