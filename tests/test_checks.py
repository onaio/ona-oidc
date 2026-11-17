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
    """Messages of the oidc.W003 warnings the configured settings raise"""
    return [m.msg for m in run_checks() if m.id == "oidc.W003"]


class RequestModeCheckTestCase(SimpleTestCase):
    """Tests for the REQUEST_MODE system check"""

    @override_settings(OPENID_CONNECT_AUTH_SERVERS=MIXED_MODE_SERVERS)
    def test_query_request_mode_warns(self):
        """Each auth server in query mode gets a warning"""
        warnings = request_mode_warnings()

        self.assertEqual(len(warnings), 2)
        self.assertIn("legacy", warnings[0])
        self.assertIn("partner", warnings[1])

    @override_settings(OPENID_CONNECT_AUTH_SERVERS=None)
    def test_unset_auth_servers_do_not_crash_checks(self):
        """An unset auth server setting raises no warning and no error"""
        self.assertEqual(request_mode_warnings(), [])
