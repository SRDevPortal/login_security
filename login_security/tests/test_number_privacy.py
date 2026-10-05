from __future__ import annotations

import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import frappe

from login_security import document_privacy, hooks


class TestLoginSecurityNumberPrivacy(unittest.TestCase):
    def test_raw_enrollment_detection_covers_rest_print_and_generic_api(self):
        self.assertTrue(
            document_privacy.is_raw_request(
                "/api/resource/Login%20Security%20Enrollment/user@example.com",
                {},
            )
        )
        self.assertTrue(
            document_privacy.is_raw_request(
                "/printview",
                {"doctype": "Login Security Enrollment", "name": "user@example.com"},
            )
        )
        self.assertTrue(
            document_privacy.is_raw_request(
                "/api/method/frappe.client.get",
                {"doctype": "Login Security Enrollment"},
            )
        )
        self.assertFalse(
            document_privacy.is_raw_request(
                "/api/resource/Login%20Security%20Event/EVENT-1",
                {},
            )
        )

    def test_raw_enrollment_guard_blocks_restricted_http_access(self):
        request = SimpleNamespace(
            path="/api/resource/Login%20Security%20Enrollment/user@example.com"
        )
        with (
            patch.object(document_privacy.frappe.local, "request", request, create=True),
            patch.object(
                document_privacy.frappe.local,
                "form_dict",
                frappe._dict(),
                create=True,
            ),
            patch("login_security.document_privacy.restricted", return_value=True),
        ):
            with self.assertRaises(frappe.PermissionError):
                document_privacy.guard_request()

    def test_full_visibility_allows_raw_enrollment_http_access(self):
        request = SimpleNamespace(
            path="/api/resource/Login%20Security%20Enrollment/user@example.com"
        )
        with (
            patch.object(document_privacy.frappe.local, "request", request, create=True),
            patch.object(
                document_privacy.frappe.local,
                "form_dict",
                frappe._dict(),
                create=True,
            ),
            patch("login_security.document_privacy.restricted", return_value=False),
        ):
            document_privacy.guard_request()

    def test_auth_hook_registers_enrollment_guard(self):
        self.assertIn(
            "login_security.document_privacy.guard_request",
            hooks.auth_hooks,
        )

    def test_user_dialog_uses_masked_status_destination(self):
        source = (
            Path(__file__).resolve().parents[1] / "public" / "js" / "user.js"
        ).read_text(encoding="utf-8-sig")

        self.assertIn(
            'default: state?.destination || __("Saved mobile number")',
            source,
        )
        self.assertNotIn("default: frm.doc.mobile_no", source)

    def test_public_challenge_never_returns_full_phone(self):
        from login_security.api.login import public_challenge

        config = frappe._dict(resend_cooldown=30)
        data = {"phone": "+919876543210", "expires_at": 120}
        storage = SimpleNamespace(clock=lambda: 20)
        with patch("login_security.api.login.store", return_value=storage):
            result = public_challenge("challenge", data, config, "accepted")

        self.assertEqual(result["destination"], "WhatsApp ending 3210")
        self.assertNotIn("9876543210", str(result))
