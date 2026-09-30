"""Delivery boundary. Future SMS adapters implement the same small contract."""

from login_security.runtime import LoginSecurityError


def validate_provider(config):
    if config.delivery_channel != "WhatsApp" or config.provider != "Interakt":
        raise LoginSecurityError("provider", "This release supports WhatsApp through Interakt.")
    if (
        not config.channel_account
        or not config.template_name
        or not config.template_language
        or not config.template_approved
    ):
        raise LoginSecurityError("provider", "Configure an approved authentication template and sender.")
    from wa_chat_hub.authentication import validate_account

    validate_account(config.channel_account)


def send(config, phone, code, reference):
    validate_provider(config)
    from wa_chat_hub.authentication import send_login_otp

    return send_login_otp(
        config.channel_account, phone, code, config.template_name, config.template_language, reference
    )
