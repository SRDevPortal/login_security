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


def normalize_public_login_url(value):
    """Accept an HTTPS origin only, never credentials, paths or header-like input."""
    value = (value or "").strip()
    if not value:
        return ""
    try:
        parsed = urlsplit(value)
        port = parsed.port
        hostname = parsed.hostname
        if (parsed.scheme != "https" or not hostname or parsed.username is not None
                or parsed.password is not None or parsed.path not in ("", "/")
                or parsed.query or parsed.fragment or "?" in value or "#" in value
                or any(c.isspace() or ord(c) < 32 for c in value) or "\\" in value):
            raise ValueError
        import re
        if ":" in hostname:
            ipaddress.IPv6Address(hostname)
        elif not all(re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?", label)
                     for label in hostname.split(".")):
            raise ValueError
        if port is not None and not 1 <= port <= 65535:
            raise ValueError
    except (ValueError, TypeError):
        raise LoginSecurityError("configuration", "Public Login URL must be an HTTPS address without credentials, a path, query or fragment.") from None
    host = hostname.lower()
    if ":" in host:
        host = "[" + host + "]"
    return "https://" + host + (":" + str(port) if port and port != 443 else "")


def configured_public_url():
    override = frappe.db.get_single_value("Login Security Settings", "public_login_url")
    return normalize_public_login_url(override) if override else frappe.conf.get("host_name") or ""



def proxy_request_host(configured_host, loopback):
    """Collapse duplicate public Hosts only from the local proxy, never mixed hosts."""
    host = frappe.local.request.host
    if loopback and configured_host and "," in host:
        values = host.split(",")
        if all(value.strip() == configured_host for value in values):
            return configured_host
    return host


def request_origin():
    """Resolve HTTPS through a loopback proxy with an explicit upstream TLS contract."""
    request = frappe.local.request
    if request.scheme == "https":
        return "https", request.host
    configured = urlsplit(configured_public_url())
    try:
        loopback = ipaddress.ip_address(request.environ.get("REMOTE_ADDR", "")).is_loopback
    except ValueError:
        loopback = False
    # Frappe's local proxy can rewrite Host to the selected site name. In that
    # case require an explicit forwarded host matching the configured public URL.
    site_host = getattr(frappe.local, "site", None)
    proxy_host = proxy_request_host(configured.netloc, loopback)
    forwarded_proto = request.headers.get("X-Forwarded-Proto")
    # Managed hosting may replace the external scheme with its internal HTTP hop.
    # This server-only opt-in asserts HTTPS is enforced before the loopback proxy.
    # It never trusts a remote peer, a different host or malformed protocol lists.
    upstream_https = (
        frappe.conf.get("login_security_https_enforced_upstream") in (True, 1)
        and forwarded_proto in (None, "http", "https")
    )
    if (
        loopback
        and configured.scheme == "https"
        and configured.netloc
        and proxy_host in (configured.netloc, site_host)
        and (forwarded_proto == "https" or upstream_https)
        and request.headers.get("X-Forwarded-Host", proxy_host) == configured.netloc
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
