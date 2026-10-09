import unittest

import frappe
from werkzeug.test import EnvironBuilder
from werkzeug.wrappers import Request

from login_security.runtime import LoginSecurityError, check_request, request_scheme


class RequestOriginTests(unittest.TestCase):
    def setUp(self):
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

    def test_site_host_rewrite_with_exact_forwarded_public_host(self):
        self.request(host="sriaas.local", forwarded_host="public.example")
        check_request()
        self.assertEqual(request_scheme(), "https")

    def test_site_host_rewrite_rejects_untrusted_or_mismatched_requests(self):
        for args in (
            {},
            {"forwarded_host": "attacker.example"},
            {"forwarded_host": "public.example", "peer": "192.0.2.5"},
            {"forwarded_host": "public.example", "origin": "https://attacker.example"},
            {"forwarded_host": "public.example", "forwarded": "http"},
            {"forwarded_host": "public.example", "forwarded": "https,http"},
        ):
            with self.subTest(args=args):
                self.request(host="sriaas.local", **args)
                with self.assertRaises(LoginSecurityError):
                    check_request()

    def test_explicit_docker_proxy_ip(self):
        frappe.local.conf.login_security_trusted_proxy_ips = ["172.19.0.2"]
        self.request(peer="172.19.0.2")
        check_request()
        self.assertEqual(request_scheme(), "https")

    def test_trusted_proxy_cannot_override_origin_host_or_protocol(self):
        frappe.local.conf.login_security_trusted_proxy_ips = ["172.19.0.2"]
        for args in (
            {"origin": "https://attacker.example"},
            {"host": "attacker.example"},
            {"forwarded_host": "attacker.example"},
            {"forwarded": "http"},
            {"forwarded": "https,http"},
        ):
            with self.subTest(args=args):
                self.request(peer="172.19.0.2", **args)
                with self.assertRaises(LoginSecurityError):
                    check_request()

    def test_proxy_configuration_fails_closed(self):
        for configured in ("172.19.0.2", ["*"], ["172.19.0.0/16"], ["nginx"], [None]):
            with self.subTest(configured=configured):
                frappe.local.conf.login_security_trusted_proxy_ips = configured
                self.request(peer="172.19.0.2")
                self.assertEqual(request_scheme(), "http")

    def test_forwarded_for_does_not_establish_proxy_trust(self):
        frappe.local.conf.login_security_trusted_proxy_ips = ["172.19.0.2"]
        self.request(peer="192.0.2.5")
        frappe.local.request.environ["HTTP_X_FORWARDED_FOR"] = "172.19.0.2"
        self.assertEqual(request_scheme(), "http")
