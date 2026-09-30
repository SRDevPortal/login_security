import concurrent.futures
import os
import subprocess
import tempfile
import time
import unittest
from unittest.mock import Mock

from redis import Redis
from redis.exceptions import ConnectionError

from login_security.challenges import ChallengeError, ChallengeStore


class ChallengeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.directory = tempfile.TemporaryDirectory(prefix="login-security-tests-")
        socket = os.path.join(cls.directory.name, "redis.sock")
        cls.process = subprocess.Popen(
            [
                "redis-server",
                "--port",
                "0",
                "--unixsocket",
                socket,
                "--unixsocketperm",
                "700",
                "--save",
                "",
                "--appendonly",
                "no",
            ],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        cls.client = Redis(unix_socket_path=socket)
        for _ in range(100):
            if not os.path.exists(socket):
                time.sleep(0.02)
                continue
            try:
                if cls.client.ping():
                    break
            except ConnectionError:
                time.sleep(0.02)
        else:
            cls.process.terminate()
            raise RuntimeError("Isolated test Redis did not start")

    @classmethod
    def tearDownClass(cls):
        cls.client.close()
        cls.process.terminate()
        cls.process.wait(timeout=5)
        cls.directory.cleanup()

    def setUp(self):
        # Only this suite's dedicated, private Redis process is flushed.
        self.client.flushdb()
        self.now = 1000
        self.store = ChallengeStore(self.client, "site-a", "test-only-secret", lambda: self.now)
        self.id, _ = self.store.create(
            purpose="staff_login", binding="browser-a", code="012345", context={"user": "a@example.test"}
        )

    def test_single_use_and_leading_zero(self):
        self.assertEqual(
            self.store.verify(self.id, "browser-a", "staff_login", "012345")["user"], "a@example.test"
        )
        with self.assertRaises(ChallengeError):
            self.store.verify(self.id, "browser-a", "staff_login", "012345")

    def test_send_limit_reports_remaining_window_without_resetting_it(self):
        from login_security.runtime import challenge_error_response

        self.store.rate("send_user", "test-user", 1, 3600)
        with self.assertRaises(ChallengeError) as caught:
            self.store.rate("send_user", "test-user", 1, 3600)
        error = caught.exception
        self.assertEqual(error.category, "send_user")
        self.assertGreater(error.retry_after, 3500)
        response = challenge_error_response(error)
        self.assertIn("OTP send limit reached", response["message"])
        self.assertEqual(response["retry_after"], error.retry_after)
        with self.assertRaises(ChallengeError) as repeated:
            self.store.rate("send_user", "test-user", 1, 3600)
        self.assertLessEqual(repeated.exception.retry_after, error.retry_after)

    def test_request_limit_message_remains_distinct(self):
        from login_security.runtime import challenge_error_response

        result = challenge_error_response(ChallengeError("rate_limited", category="start_ip", retry_after=61))
        self.assertEqual(result["message"], "Too many attempts. Try again in 2 minute(s).")
        self.assertNotIn("retry_after", challenge_error_response(ChallengeError("incorrect")))

    def test_wrong_browser_purpose_and_site(self):
        for browser, purpose in (("browser-b", "staff_login"), ("browser-a", "enrollment")):
            with self.assertRaises(ChallengeError):
                self.store.verify(self.id, browser, purpose, "012345")
        other = ChallengeStore(self.client, "site-b", "test-only-secret", lambda: self.now)
        with self.assertRaises(ChallengeError):
            other.verify(self.id, "browser-a", "staff_login", "012345")

    def test_no_plaintext_in_store(self):
        raw = self.client.get(self.store.key(self.id))
        self.assertNotIn(b"012345", raw)
        self.assertNotIn(b"browser-a", raw)
        self.assertEqual(self.client.ttl(self.store.key(self.id)), 600)

    def test_expiry(self):
        self.now += 301
        with self.assertRaisesRegex(ChallengeError, "expired"):
            self.store.verify(self.id, "browser-a", "staff_login", "012345")

    def test_attempt_budget_survives_resend(self):
        for _ in range(4):
            with self.assertRaisesRegex(ChallengeError, "incorrect"):
                self.store.verify(self.id, "browser-a", "staff_login", "bad")
        self.now += 60
        self.store.resend(self.id, "browser-a", "staff_login", "654321")
        with self.assertRaisesRegex(ChallengeError, "incorrect"):
            self.store.verify(self.id, "browser-a", "staff_login", "012345")
        with self.assertRaisesRegex(ChallengeError, "exhausted"):
            self.store.verify(self.id, "browser-a", "staff_login", "654321")

    def test_resend_cooldown_replacement_and_lifetime(self):
        with self.assertRaisesRegex(ChallengeError, "cooldown"):
            self.store.resend(self.id, "browser-a", "staff_login", "654321")
        self.now += 450
        data = self.store.resend(self.id, "browser-a", "staff_login", "654321")
        self.assertEqual(data["expires_at"], 1600)
        with self.assertRaises(ChallengeError):
            self.store.verify(self.id, "browser-a", "staff_login", "012345")
        self.store.verify(self.id, "browser-a", "staff_login", "654321")

    def test_concurrent_verification_exactly_one_winner(self):
        def verify(_):
            try:
                self.store.verify(self.id, "browser-a", "staff_login", "012345")
                return True
            except ChallengeError:
                return False

        with concurrent.futures.ThreadPoolExecutor(max_workers=12) as pool:
            self.assertEqual(sum(pool.map(verify, range(24))), 1)

    def test_rate_limit_does_not_reset_with_new_challenge(self):
        for _ in range(3):
            self.store.rate("user", "a", 3, 60)
        with self.assertRaisesRegex(ChallengeError, "rate_limited"):
            self.store.rate("user", "a", 3, 60)

    def test_rejected_delivery_allows_recovery_but_not_otp(self):
        self.store.invalidate_code(self.id, "012345")
        with self.assertRaises(ChallengeError):
            self.store.verify(self.id, "browser-a", "staff_login", "012345")
        self.store.consume_for_recovery(self.id, "browser-a")
        with self.assertRaises(ChallengeError):
            self.store.consume_for_recovery(self.id, "browser-a")

    def test_invalidate_does_not_resurrect_consumed_challenge(self):
        self.store.verify(self.id, "browser-a", "staff_login", "012345")
        self.store.invalidate_code(self.id, "012345")
        self.assertIsNone(self.client.get(self.store.key(self.id)))

    def test_late_rejection_cannot_invalidate_resend(self):
        self.now += 60
        self.store.resend(self.id, "browser-a", "staff_login", "654321")
        self.store.invalidate_code(self.id, "012345")
        self.store.verify(self.id, "browser-a", "staff_login", "654321")

    def test_redis_unavailable_fails(self):
        client = Mock()
        client.eval.side_effect = ConnectionError("test Redis unavailable")
        unavailable = ChallengeStore(client, "a", "b")
        with self.assertRaises(ConnectionError):
            unavailable.verify(self.id, "browser-a", "staff_login", "012345")
