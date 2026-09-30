"""Small pure primitives shared by login, enrollment and recovery."""

import hashlib
import hmac
import json
import secrets


def digest(secret, purpose, *parts):
    value = json.dumps([purpose, *parts], separators=(",", ":"), ensure_ascii=True)
    return hmac.new(secret.encode(), value.encode(), hashlib.sha256).hexdigest()


def new_code():
    return f"{secrets.randbelow(1_000_000):06d}"


def normalize_phone(phone):
    import phonenumbers

    if not isinstance(phone, str) or not phone.startswith("+"):
        raise ValueError("Use an international phone number beginning with +.")
    try:
        parsed = phonenumbers.parse(phone, None)
    except phonenumbers.NumberParseException:
        raise ValueError("Enter a valid international phone number.") from None
    if not phonenumbers.is_valid_number(parsed):
        raise ValueError("Enter a valid international phone number.")
    return phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.E164)
