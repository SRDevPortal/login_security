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


def trusted_proxy(peer):
    """Trust the immediate peer, never client-supplied forwarding chains."""
    try:
        address = ipaddress.ip_address(peer)
    except (ValueError, TypeError):
        return False
    if address.is_loopback:
        return True
    configured = frappe.conf.get("login_security_trusted_proxy_ips") or []
    if not isinstance(configured, (list, tuple)):
        return False
    for value in configured:
        try:
            if address == ipaddress.ip_address(value):
                return True
        except (ValueError, TypeError):
            continue
    return False


def request_origin():
    """Recognize public HTTPS through explicitly trusted proxies."""
    request = frappe.local.request
    if request.scheme == "https":
        return "https", request.host
    configured = urlsplit(frappe.conf.get("host_name") or "")
    site_host = getattr(frappe.local, "site", None)
    if (
        trusted_proxy(request.environ.get("REMOTE_ADDR", ""))
        and configured.scheme == "https"
        and configured.netloc
        and request.host in (configured.netloc, site_host)
        and request.headers.get("X-Forwarded-Proto") == "https"
        and request.headers.get("X-Forwarded-Host", request.host) == configured.netloc
    ):
        return "https", configured.netloc
    return request.scheme, request.host


def request_scheme():
    return request_origin()[0]


def check_request():
    request = frappe.local.request
    if request.method != "POST" or request.headers.get("X-Login-Security") != "1":
        raise LoginSecurityError("request", "Invalid login request.")
    origin = request.headers.get("Origin") or request.headers.get("Referer")
    parsed = urlsplit(origin or "")
    scheme, host = request_origin()
    if parsed.scheme != scheme or parsed.netloc != host:
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


def endpoint(fn=None, *, check_origin=True):
    """Never allow a secret-bearing exception/response to reach Frappe error snapshots."""

    if fn is None:
        return functools.partial(endpoint, check_origin=check_origin)

    @functools.wraps(fn)
    def wrapped(*args, **kwargs):
        try:
            if check_origin:
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
