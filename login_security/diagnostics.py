"""Read-only inventory; deliberately excludes credentials and phone numbers."""

import frappe


def inventory():
    return {
        "site": frappe.local.site,
        "frappe_version": frappe.__version__,
        "login_security_installed": "login_security" in frappe.get_installed_apps(),
        "login_security_enabled": bool(frappe.db.get_single_value("Login Security Settings", "enabled"))
        if "login_security" in frappe.get_installed_apps()
        else False,
        "wa_chat_hub_installed": "wa_chat_hub" in frappe.get_installed_apps(),
        "native_2fa_enabled": bool(frappe.get_system_settings("enable_two_factor_auth")),
        "password_login_disabled": bool(frappe.get_system_settings("disable_user_pass_login")),
        "email_link_login_enabled": bool(frappe.get_system_settings("login_with_email_link")),
        "enabled_social_providers": frappe.db.count("Social Login Key", {"enable_social_login": 1}),
        "enabled_staff_count": frappe.db.count("User", {"enabled": 1, "user_type": "System User"}),
        "redis_available": bool(frappe.cache.ping()),
        "coverage_version": int(
            frappe.db.get_single_value("Login Security Settings", "coverage_version") or 0
        ),
        "user_custom_fields": frappe.db.count("Custom Field", {"dt": "User", "module": "Login Security"}),
        "users_with_verification_enabled": frappe.db.count("User", {"login_security_enabled": 1})
        if frappe.get_meta("User").has_field("login_security_enabled")
        else 0,
    }


@frappe.whitelist(methods=["POST"])
def request_report():
    """Observe the browser request without invoking enrollment or the origin gate."""
    import ipaddress
    from urllib.parse import urlsplit

    from login_security.runtime import (
        LoginSecurityError, check_request, configured_public_url, request_origin, proxy_request_host,
    )
    from login_security.user_policy import is_operator

    if not is_operator():
        raise frappe.PermissionError
    request = frappe.local.request
    if request.method != "POST" or request.headers.get("X-Login-Security") != "1":
        raise frappe.PermissionError

    def origin_only(value):
        # Never return Referer paths/queries, URL credentials or arbitrary bodies.
        try:
            parsed = urlsplit(value or "")
            if parsed.username is not None or parsed.password is not None:
                return "[invalid origin]"
            return (parsed.scheme + "://" + parsed.netloc)[:256] if parsed.netloc else ""
        except ValueError:
            return "[invalid origin]"

    peer = request.environ.get("REMOTE_ADDR", "")
    try:
        loopback = ipaddress.ip_address(peer).is_loopback
    except ValueError:
        loopback = False
    report = {
        "diagnostic_version": "origin-report-v2",
        "site": frappe.local.site,
        "https_enforced_upstream": frappe.conf.get("login_security_https_enforced_upstream") in (True, 1),
        "request": {
            "scheme": request.scheme,
            "host": request.host[:256],
            "origin": origin_only(request.headers.get("Origin")),
            "referer_origin": origin_only(request.headers.get("Referer")),
            "connection_peer": peer[:64],
            "peer_is_loopback": loopback,
            "forwarded_proto": request.headers.get("X-Forwarded-Proto", "")[:64],
            "forwarded_host": request.headers.get("X-Forwarded-Host", "")[:256],
        },
    }
    try:
        configured = urlsplit(configured_public_url())
        proxy_host = proxy_request_host(configured.netloc, loopback)
        report["normalized_proxy_host"] = proxy_host[:256]
        scheme, host = request_origin()
        proto = request.headers.get("X-Forwarded-Proto")
        report["configured_origin"] = origin_only(configured.geturl())
        report["resolved_origin"] = origin_only(scheme + "://" + host)
        report["checks"] = {
            "configured_https": configured.scheme == "https" and bool(configured.netloc),
            "loopback_peer": loopback,
            "host_matches": proxy_host in (configured.netloc, frappe.local.site),
            "forwarded_host_matches": request.headers.get("X-Forwarded-Host", proxy_host) == configured.netloc,
            "protocol_recognized": proto == "https" or (
                report["https_enforced_upstream"] and proto in (None, "http", "https")
            ),
            "browser_origin_matches": origin_only(request.headers.get("Origin") or request.headers.get("Referer")) == report["resolved_origin"],
        }
        check_request()
        report["validation"] = {"passed": True, "code": "ok"}
    except LoginSecurityError as exc:
        report["validation"] = {"passed": False, "code": exc.code, "message": exc.message}
    except ValueError:
        report["validation"] = {"passed": False, "code": "invalid_request_metadata"}
    return report


if __name__ == "__main__":
    import json
    import os
    import sys

    frappe.init(site=sys.argv[1], sites_path=os.path.join(os.getcwd(), "sites"))
    try:
        frappe.connect()
        print(json.dumps(inventory(), indent=2))
    finally:
        frappe.destroy()
