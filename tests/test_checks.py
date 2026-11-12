"""Tests for module oidc.checks"""

from django.core.checks import run_checks
from django.test import SimpleTestCase, override_settings

QUERY_MODE_SERVERS = {
    "legacy": {"REQUEST_MODE": "query"},
    "modern": {"REQUEST_MODE": "form_post"},
    "default": {},
}


class RequestModeCheckTestCase(SimpleTestCase):
    """Tests for the REQUEST_MODE system check"""

    @override_settings(OPENID_CONNECT_AUTH_SERVERS=QUERY_MODE_SERVERS)
    def test_query_request_mode_warns(self):
        """Each auth server in query mode gets a warning"""
        warnings = [m for m in run_checks() if m.id == "oidc.W001"]

        self.assertEqual(len(warnings), 1)
        self.assertIn("legacy", warnings[0].msg)

    @override_settings(
        OPENID_CONNECT_AUTH_SERVERS={
            name: server
            for name, server in QUERY_MODE_SERVERS.items()
            if name != "legacy"
        }
    )
    def test_body_request_mode_does_not_warn(self):
        """Auth servers that send credentials in the body raise no warning"""
        self.assertNotIn("oidc.W001", [m.id for m in run_checks()])
