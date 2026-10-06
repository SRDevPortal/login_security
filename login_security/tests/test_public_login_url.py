import unittest
from unittest.mock import Mock, patch
import frappe
from login_security.runtime import LoginSecurityError, configured_public_url, normalize_public_login_url


class PublicLoginURLTests(unittest.TestCase):
    def test_valid_origins_and_normalization(self):
        for value, expected in [("", ""), (" https://PUBLIC.example/ ", "https://public.example"),
                                ("https://public.example:443", "https://public.example"),
                                ("https://public.example:8443", "https://public.example:8443"),
                                ("https://[::1]:8443", "https://[::1]:8443")]:
            self.assertEqual(normalize_public_login_url(value), expected)

    def test_invalid_addresses(self):
        for value in ["http://public.example", "https://", "https://user:pass@public.example",
                      "https://public.example/login", "https://public.example?x=1",
                      "https://public.example#login", "https://public.example:bad",
                      "https://public.example:0", "https://public.example:65536",
                      "https://public.example\n.evil", "https://public.example\\evil",
                      "https://-bad.example"]:
            with self.subTest(value=value), self.assertRaises(LoginSecurityError):
                normalize_public_login_url(value)

    def test_saved_override_precedes_site_config_and_blank_falls_back(self):
        db = Mock()
        with patch.object(frappe.local, "db", db, create=True), \
             patch.object(frappe.local, "conf", frappe._dict(host_name="https://old.example"), create=True):
            db.get_single_value.return_value = "https://new.example/"
            self.assertEqual(configured_public_url(), "https://new.example")
            db.get_single_value.return_value = ""
            self.assertEqual(configured_public_url(), "https://old.example")
