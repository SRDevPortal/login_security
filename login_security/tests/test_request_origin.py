import unittest
from unittest.mock import patch

import frappe
from werkzeug.test import EnvironBuilder
from werkzeug.wrappers import Request

from login_security.runtime import LoginSecurityError, check_request, request_scheme


class RequestOriginTests(unittest.TestCase):
    def setUp(self):
        url_patch = patch("login_security.runtime.configured_public_url", return_value="https://public.example")
        self.url_reader = url_patch.start()
        self.addCleanup(url_patch.stop)
        self.old_site = getattr(frappe.local, "site", None)
        frappe.local.site = "sriaas.local"
        self.old_conf = getattr(frappe.local, "conf", None)
        self.old_request = getattr(frappe.local, "request", None)
        frappe.local.conf = frappe._dict(host_name="https://public.example", developer_mode=0)

    def tearDown(self):
        frappe.local.site = self.old_site
        frappe.local.conf = self.old_conf
        frappe.local.request = self.old_request

    def request(
        self,
        origin="https://public.example",
        peer="127.0.0.1",
        host="public.example",
        forwarded="https",
        scheme="http",
        forwarded_host=None,
    ):
        headers = {"Origin": origin, "X-Login-Security": "1", "X-Forwarded-Proto": forwarded}
        if forwarded_host is not None:
            headers["X-Forwarded-Host"] = forwarded_host
        frappe.local.request = Request(
            EnvironBuilder(
                method="POST",
                base_url=f"{scheme}://{host}",
                headers=headers,
                environ_overrides={"REMOTE_ADDR": peer},
            ).get_environ()
        )

    def test_configured_https_through_loopback_proxy(self):
        self.request()
        check_request()
        self.assertEqual(request_scheme(), "https")

    def test_cross_origin_still_rejected(self):
        self.request(origin="https://attacker.example")
        with self.assertRaises(LoginSecurityError):
            check_request()

    def test_untrusted_peer_cannot_claim_https(self):
        self.request(peer="192.0.2.5")
        self.assertEqual(request_scheme(), "http")
        with self.assertRaises(LoginSecurityError):
            check_request()

    def test_unconfigured_host_and_spoofed_forwarded_host_rejected(self):
        for args in (
            {"host": "other.example", "origin": "https://other.example"},
            {"forwarded_host": "attacker.example"},
            {"forwarded": "https,http"},
        ):
            with self.subTest(args=args):
                self.request(**args)
                with self.assertRaises(LoginSecurityError):
                    check_request()

    def test_direct_https_and_local_development_still_work(self):
        self.request(scheme="https", peer="192.0.2.5")
        check_request()
        frappe.local.conf.developer_mode = 1
        self.request(host="localhost", origin="http://localhost", forwarded="http")
        check_request()

    def test_plain_http_public_host_still_rejected(self):
        self.request(origin="http://public.example", forwarded="http")
        with self.assertRaises(LoginSecurityError) as error:
            check_request()
        self.assertEqual(error.exception.code, "https")

    def test_site_host_rewrite_with_configured_forwarded_host(self):
        self.request(host="sriaas.local", forwarded_host="public.example")
        check_request()
        self.assertEqual(request_scheme(), "https")

    def test_site_host_rewrite_rejects_missing_spoofed_or_untrusted_headers(self):
        for args in ({}, {"forwarded_host": "attacker.example"},
                     {"forwarded_host": "public.example", "peer": "192.0.2.5"},
                     {"forwarded_host": "public.example", "origin": "https://attacker.example"},
                     {"forwarded_host": "public.example", "forwarded": "https,http"}):
            with self.subTest(args=args):
                self.request(host="sriaas.local", **args)
                with self.assertRaises(LoginSecurityError):
                    check_request()

    def test_override_accepts_new_tunnel_and_rejects_old_tunnel(self):
        self.url_reader.return_value = "https://new.example"
        self.request(host="sriaas.local", origin="https://new.example", forwarded_host="new.example")
        check_request()
        self.request(host="sriaas.local", forwarded_host="public.example")
        with self.assertRaises(LoginSecurityError):
            check_request()

    def test_override_does_not_trust_remote_proxy_or_foreign_origin(self):
        self.url_reader.return_value = "https://new.example"
        for args in ({"peer": "192.0.2.5", "origin": "https://new.example"},
                     {"origin": "https://attacker.example"}):
            self.request(host="sriaas.local", forwarded_host="new.example", **args)
            with self.assertRaises(LoginSecurityError):
                check_request()

    def test_upstream_https_opt_in_handles_internal_http_and_secure_cookie_scheme(self):
        frappe.local.conf.login_security_https_enforced_upstream = 1
        for proto in ("http", "https", None):
            with self.subTest(proto=proto):
                self.request(forwarded="http")
                headers = dict(frappe.local.request.headers)
                headers.pop("X-Forwarded-Proto", None)
                if proto is not None:
                    headers["X-Forwarded-Proto"] = proto
                frappe.local.request = Request(EnvironBuilder(
                    method="POST", base_url="http://public.example", headers=headers,
                    environ_overrides={"REMOTE_ADDR": "127.0.0.1"},
                ).get_environ())
                check_request()
                self.assertEqual(request_scheme(), "https")

    def test_upstream_https_opt_in_preserves_origin_host_and_peer_checks(self):
        frappe.local.conf.login_security_https_enforced_upstream = 1
        for args in (
            {"peer": "172.19.0.2"},
            {"peer": "invalid"},
            {"origin": "https://attacker.example"},
            {"origin": "http://public.example"},
            {"host": "attacker.example", "origin": "https://attacker.example"},
            {"forwarded_host": "attacker.example"},
            {"forwarded": "https,http"},
            {"forwarded": "ftp"},
            {"host": "sriaas.local"},
        ):
            with self.subTest(args=args):
                self.request(**dict({"forwarded": "http"}, **args))
                with self.assertRaises(LoginSecurityError):
                    check_request()

    def test_upstream_https_opt_in_allows_bound_site_host_rewrite(self):
        frappe.local.conf.login_security_https_enforced_upstream = 1
        self.request(host="sriaas.local", forwarded="http", forwarded_host="public.example")
        check_request()
        self.assertEqual(request_scheme(), "https")

    def test_upstream_https_opt_in_requires_explicit_flag_and_https_configuration(self):
        for flag in (None, 0, "false", "true", "1"):
            with self.subTest(flag=flag):
                frappe.local.conf.login_security_https_enforced_upstream = flag
                self.request(forwarded="http")
                with self.assertRaises(LoginSecurityError):
                    check_request()
        frappe.local.conf.login_security_https_enforced_upstream = 1
        for url in ("", "http://public.example"):
            with self.subTest(url=url):
                self.url_reader.return_value = url
                self.request(forwarded="http")
                with self.assertRaises(LoginSecurityError):
                    check_request()
