import unittest
from types import SimpleNamespace
from unittest.mock import Mock, patch

import requests
from wa_chat_hub.authentication import send_login_otp, validate_account


class DeliveryTests(unittest.TestCase):
    def setUp(self):
        self.account = SimpleNamespace(
            is_active=1,
            channel_type="Interakt",
            interakt_base_url="",
            get_password=lambda *a, **k: "test-only-key",
        )

    def send(self):
        return send_login_otp(
            "test-account", "+14155552671", "012345", "staff_login_otp", "en", "opaque-reference"
        )

    @patch("wa_chat_hub.authentication.frappe.get_doc")
    @patch("wa_chat_hub.authentication.requests.post")
    def test_matching_body_and_button_no_payload_returned(self, post, get_doc):
        get_doc.return_value = self.account
        post.return_value = Mock(status_code=201, json=lambda: {"result": True, "id": "message-id"})
        result = self.send()
        payload = post.call_args.kwargs["json"]
        self.assertEqual(payload["template"]["bodyValues"], ["012345"])
        self.assertEqual(payload["template"]["buttonValues"], {"0": ["012345"]})
        self.assertEqual(result, {"outcome": "accepted", "message_id": "message-id"})
        self.assertFalse(post.call_args.kwargs["allow_redirects"])

    @patch("wa_chat_hub.authentication.frappe.get_doc")
    @patch("wa_chat_hub.authentication.requests.post")
    def test_timeout_redacted(self, post, get_doc):
        get_doc.return_value = self.account
        post.side_effect = requests.Timeout("sensitive 012345 test-only-key")
        self.assertEqual(self.send(), {"outcome": "unknown"})

    @patch("wa_chat_hub.authentication.frappe.get_doc")
    @patch("wa_chat_hub.authentication.requests.post")
    def test_rejection_does_not_return_body(self, post, get_doc):
        get_doc.return_value = self.account
        post.return_value = Mock(status_code=400, text="sensitive 012345")
        self.assertEqual(self.send(), {"outcome": "rejected"})

    @patch("wa_chat_hub.authentication.frappe.get_doc")
    def test_custom_endpoint_rejected(self, get_doc):
        self.account.interakt_base_url = "https://untrusted.example/message/"
        get_doc.return_value = self.account
        with self.assertRaises(ValueError):
            validate_account("test-account")
