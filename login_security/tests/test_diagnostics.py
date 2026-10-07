import json
import unittest
from unittest.mock import patch

import frappe
from werkzeug.test import EnvironBuilder
from werkzeug.wrappers import Request

from login_security.diagnostics import request_report
from login_security.tests import test_request_origin as origin_tests


class DiagnosticsTests(unittest.TestCase):
    setUp = origin_tests.RequestOriginTests.setUp
    tearDown = origin_tests.RequestOriginTests.tearDown
    request = origin_tests.RequestOriginTests.request

    def test_report_reproduces_failure_without_secret_metadata(self):
        self.request(forwarded="http")
        with patch("login_security.user_policy.is_operator", return_value=True):
            report = request_report()
        self.assertFalse(report["validation"]["passed"])
        self.assertEqual(report["validation"]["code"], "origin")
        self.assertFalse(report["checks"]["protocol_recognized"])
        self.assertNotIn("cookies", report["request"])

    def test_report_accepts_override_and_redacts_referer_and_credentials(self):
        frappe.local.conf.login_security_https_enforced_upstream = 1
        frappe.local.request = Request(EnvironBuilder(
            method="POST", base_url="http://public.example",
            headers={"X-Login-Security": "1", "X-Forwarded-Proto": "http",
                     "Referer": "https://public.example/private?password=TOPSECRET",
                     "Authorization": "token TOPSECRET", "Cookie": "sid=TOPSECRET"},
            environ_overrides={"REMOTE_ADDR": "127.0.0.1"},
        ).get_environ())
        with patch("login_security.user_policy.is_operator", return_value=True):
            report = request_report()
        self.assertTrue(report["validation"]["passed"])
        self.assertEqual(report["resolved_origin"], "https://public.example")
        self.assertNotIn("TOPSECRET", json.dumps(report))
        self.assertNotIn("/private", json.dumps(report))

    def test_report_rejects_nonoperator(self):
        self.request()
        with patch("login_security.user_policy.is_operator", return_value=False):
            with self.assertRaises(frappe.PermissionError):
                request_report()

    def test_report_requires_request_header(self):
        frappe.local.request = Request(EnvironBuilder(
            method="POST", base_url="http://public.example",
        ).get_environ())
        with patch("login_security.user_policy.is_operator", return_value=True):
            with self.assertRaises(frappe.PermissionError):
                request_report()

    def test_report_identifies_normalized_duplicate_public_host(self):
        frappe.local.conf.login_security_https_enforced_upstream = 1
        self.request(host="public.example,public.example", forwarded="http")
        with patch("login_security.user_policy.is_operator", return_value=True):
            report = request_report()
        self.assertEqual(report["diagnostic_version"], "origin-report-v2")
        self.assertEqual(report["request"]["host"], "public.example,public.example")
        self.assertEqual(report["normalized_proxy_host"], "public.example")
        self.assertTrue(report["checks"]["host_matches"])
        self.assertTrue(report["checks"]["forwarded_host_matches"])
        self.assertTrue(report["validation"]["passed"])
