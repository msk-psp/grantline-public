"""Deployment language preserves each user's explicit language choice."""

from grantline.i18n import negotiate


def test_configured_korean_overrides_browser_default():
    assert negotiate("", "", "en-US,en;q=0.9", "ko") == "ko"


def test_user_choice_overrides_deployment_language():
    assert negotiate("ja", "grantline_lang=en", "ko", "ko") == "ja"
    assert negotiate("", "grantline_lang=en", "ko", "ko") == "en"


def test_unconfigured_deployment_preserves_browser_negotiation():
    assert negotiate("", "", "ja;q=0.8,en;q=0.5") == "ja"
    assert negotiate("", "", "") == "en"


test_configured_korean_overrides_browser_default()
test_user_choice_overrides_deployment_language()
test_unconfigured_deployment_preserves_browser_negotiation()
