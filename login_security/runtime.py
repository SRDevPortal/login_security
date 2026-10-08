import functools
import ipaddress
from urllib.parse import urlsplit

import frappe
from redis import Redis

from login_security.challenges import ChallengeError, ChallengeStore

COOKIE = "login_security_binding"


class LoginSecurityError(Exception):
    def __init__(self, code, message):
        self.code, self.message = code, message


def secret():
    value = frappe.conf.get("encryption_key")
    if not value:
        raise LoginSecurityError(
            "configuration", "Login verification is not configured. Contact an administrator."
        )
    return value


def store():
    return ChallengeStore(Redis(connection_pool=frappe.cache.connection_pool), frappe.local.site, secret())


def request_scheme():
    """Honor HTTPS termination only from a loopback proxy for the configured host."""
    request = frappe.local.request
    if request.scheme == "https":
        return "https"
    configured = urlsplit(frappe.conf.get("host_name") or "")
    try:
        loopback = ipaddress.ip_address(request.environ.get("REMOTE_ADDR", "")).is_loopback
    except ValueError:
        loopback = False
    if (
        loopback
        and configured.scheme == "https"
        and configured.netloc == request.host
        and request.headers.get("X-Forwarded-Proto") == "https"
        and request.headers.get("X-Forwarded-Host", request.host) == configured.netloc
    ):
        return "https"
    return request.scheme


def check_request():
    request = frappe.local.request
    if request.method != "POST" or request.headers.get("X-Login-Security") != "1":
        raise LoginSecurityError("request", "Invalid login request.")
    origin = request.headers.get("Origin") or request.headers.get("Referer")
    parsed = urlsplit(origin or "")
    scheme = request_scheme()
    if parsed.scheme != scheme or parsed.netloc != request.host:
        raise LoginSecurityError("origin", "Reload this page on the site's configured address and try again.")
    local_development = frappe.conf.get("developer_mode") and request.host.split(":")[0] in {
        "localhost",
        "127.0.0.1",
        "site1.local",
    }
    if scheme != "https" and not local_development:
        raise LoginSecurityError("https", "Secure HTTPS is required for login verification.")


def binding():
    value = frappe.local.request.cookies.get(COOKIE, "")
    if len(value) != 43:
        raise ChallengeError("invalid")
    return value


def challenge_error_response(exc):
    result = {
        "status": "error",
        "code": str(exc),
        "message": {
            "cooldown": "Please wait before requesting another code.",
            "rate_limited": "Too many attempts. Please try again later.",
        }.get(str(exc), "Code invalid, expired or already used. Try again or restart login."),
    }
    if str(exc) == "rate_limited" and exc.retry_after:
        result["retry_after"] = exc.retry_after
        minutes = max(1, (exc.retry_after + 59) // 60)
        if exc.category in {"send_user", "send_phone", "send_ip"}:
            result["message"] = (
                f"OTP send limit reached. Try again in {minutes} minute(s). "
                "Login, resend and number-verification sends share this allowance, "
                "including rejected delivery attempts."
            )
        else:
            result["message"] = f"Too many attempts. Try again in {minutes} minute(s)."
    return result


def endpoint(fn):
    """Never allow a secret-bearing exception/response to reach Frappe error snapshots."""

    @functools.wraps(fn)
    def wrapped(*args, **kwargs):
        try:
            check_request()
            return fn(*args, **kwargs)
        except ChallengeError as exc:
            frappe.db.rollback()
            return challenge_error_response(exc)
        except LoginSecurityError as exc:
            frappe.db.rollback()
            return {"status": "error", "code": exc.code, "message": exc.message}
        except (frappe.AuthenticationError, frappe.SecurityException, frappe.PermissionError):
            frappe.db.rollback()
            return {
                "status": "error",
                "code": "authentication",
                "message": "Unable to authenticate. Check your details or contact an administrator.",
            }
        except Exception:  # noqa: BLE001 - boundary must suppress secret-bearing third-party exceptions
            # No exception string/traceback: transports can retain payloads and passwords in locals.
            frappe.db.rollback()
            frappe.logger("login_security", with_more_info=False).error(
                "Login Security request failed; sensitive details suppressed"
            )
            return {
                "status": "error",
                "code": "unavailable",
                "message": "Login verification is unavailable. Please try again later.",
            }
        finally:
            for key in ("pwd", "password", "code", "recovery_code"):
                frappe.form_dict.pop(key, None)
            frappe.local.response.pop("exc", None)
            frappe.local.response.pop("_server_messages", None)

    return wrapped


def no_store_response(request, response):
    if request.path.startswith("/api/method/login_security.") or request.path == "/login":
        response.headers["Cache-Control"] = "no-store"
