"""Tests for module oidc.checks"""

from django.core.checks import run_checks
from django.test import SimpleTestCase, override_settings

BODY_MODE_SERVERS = {
    "modern": {"REQUEST_MODE": "form_post"},
    "default": {},
}
MIXED_MODE_SERVERS = {
    "legacy": {"REQUEST_MODE": "query"},
    "partner": {"REQUEST_MODE": "query"},
    **BODY_MODE_SERVERS,
}


def request_mode_warnings():
    return [m.msg for m in run_checks() if m.id == "oidc.W001"]


class RequestModeCheckTestCase(SimpleTestCase):
    """Tests for the REQUEST_MODE system check"""

    @override_settings(OPENID_CONNECT_AUTH_SERVERS=MIXED_MODE_SERVERS)
    def test_query_request_mode_warns(self):
        """Each auth server in query mode gets a warning"""
        warnings = request_mode_warnings()

        self.assertEqual(len(warnings), 2)
        self.assertIn("legacy", warnings[0])
        self.assertIn("partner", warnings[1])

    @override_settings(OPENID_CONNECT_AUTH_SERVERS=BODY_MODE_SERVERS)
    def test_body_request_mode_does_not_warn(self):
        """Auth servers that send credentials in the body raise no warning"""
        self.assertEqual(request_mode_warnings(), [])

    def test_malformed_settings_do_not_crash_checks(self):
        """A setting that isn't a mapping of mappings is skipped, not raised"""
        cases = {
            "None value": (None, 0),
            "non-mapping entry": ({"broken": None, **MIXED_MODE_SERVERS}, 2),
        }
        for name, (servers, expected) in cases.items():
            with (
                self.subTest(name),
                override_settings(OPENID_CONNECT_AUTH_SERVERS=servers),
            ):
                self.assertEqual(len(request_mode_warnings()), expected)
