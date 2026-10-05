"""Protect raw verified-phone enrollment records at HTTP boundaries."""
from __future__ import annotations

import json
from urllib.parse import unquote

import frappe

from login_security.number_privacy import restricted


RAW_DOCTYPES = frozenset({"Login Security Enrollment"})
GENERIC_PREFIXES = (
    "frappe.client.",
    "frappe.desk.",
    "frappe.model.",
    "frappe.core.",
    "frappe.utils.print_format.",
)


def contains_raw_target(value):
    if isinstance(value, dict):
        return any(contains_raw_target(item) for item in value.values())
    if isinstance(value, (list, tuple)):
        return any(contains_raw_target(item) for item in value)
    if not isinstance(value, str):
        return False
    if value in RAW_DOCTYPES:
        return True
    if value.lstrip().startswith(("{", "[")):
        try:
            return contains_raw_target(json.loads(value))
        except (TypeError, ValueError):
            return False
    return False


def is_raw_request(path, args):
    path = unquote(path or "")
    parts = path.strip("/").split("/")
    if len(parts) >= 3 and parts[:2] == ["api", "resource"]:
        return parts[2] in RAW_DOCTYPES
    if len(parts) >= 4 and parts[:3] in (
        ["api", "v1", "resource"],
        ["api", "v2", "document"],
    ):
        return parts[3] in RAW_DOCTYPES

    method = args.get("cmd") or ""
    for prefix in ("/api/method/", "/api/v1/method/", "/api/v2/method/"):
        if path.startswith(prefix):
            method = path[len(prefix):]
            break
    generic = method.startswith(GENERIC_PREFIXES) or method in {
        "run_doc_method",
        "frappe.handler.run_doc_method",
    }
    return (generic or path.rstrip("/") == "/printview") and contains_raw_target(args)


def guard_request():
    request = getattr(frappe.local, "request", None)
    args = getattr(frappe.local, "form_dict", {}) or {}
    if request and is_raw_request(request.path, args) and restricted():
        raise frappe.PermissionError(
            "Verified phone enrollment records require full-number visibility. "
            "Use the Login Security status shown on the User form."
        )
