"""Tests for module oidc.utils"""

from django.test import TestCase
from django.test.utils import override_settings

from rest_framework.test import APIRequestFactory

from oidc.utils import (
    get_login_query_param_allowlist,
    is_safe_login_redirect,
)


class TestGetLoginQueryParamAllowlist(TestCase):
    @override_settings(
        OPENID_CONNECT_AUTH_SERVERS={
            "default": {
                "LOGIN_QUERY_PARAM_ALLOWLIST": ["prompt", "ui_locales"],
            },
        }
    )
    def test_returns_configured_allowlist(self):
        self.assertEqual(
            get_login_query_param_allowlist("default"),
            frozenset({"prompt", "ui_locales"}),
        )

    @override_settings(
        OPENID_CONNECT_AUTH_SERVERS={"default": {"CLIENT_ID": "client"}}
    )
    def test_returns_empty_when_key_missing(self):
        self.assertEqual(get_login_query_param_allowlist("default"), frozenset())

    @override_settings(OPENID_CONNECT_AUTH_SERVERS={})
    def test_returns_empty_for_unknown_auth_server(self):
        self.assertEqual(get_login_query_param_allowlist("default"), frozenset())


class TestIsSafeLoginRedirect(TestCase):
    def setUp(self):
        self.factory = APIRequestFactory()

    def _request(self):
        return self.factory.get("/")

    def test_path_only_is_safe(self):
        self.assertTrue(
            is_safe_login_redirect("/dashboard", "default", self._request())
        )

    def test_empty_url_is_unsafe(self):
        self.assertFalse(is_safe_login_redirect("", "default", self._request()))
        self.assertFalse(is_safe_login_redirect(None, "default", self._request()))

    def test_same_host_absolute_url_is_safe(self):
        request = self._request()
        same_host_url = f"http://{request.get_host()}/dashboard"
        self.assertTrue(is_safe_login_redirect(same_host_url, "default", request))

    def test_other_host_without_allowlist_is_unsafe(self):
        self.assertFalse(
            is_safe_login_redirect(
                "https://attacker.example/phish", "default", self._request()
            )
        )

    @override_settings(
        OPENID_CONNECT_AUTH_SERVERS={
            "default": {"LOGIN_REDIRECT_ALLOWED_HOSTS": ["spa.example.com"]},
        }
    )
    def test_other_host_with_allowlist_is_safe(self):
        self.assertTrue(
            is_safe_login_redirect(
                "https://spa.example.com/dashboard", "default", self._request()
            )
        )

    @override_settings(
        OPENID_CONNECT_AUTH_SERVERS={
            "default": {"LOGIN_REDIRECT_ALLOWED_HOSTS": ["spa.example.com"]},
        }
    )
    def test_other_host_outside_allowlist_is_unsafe(self):
        self.assertFalse(
            is_safe_login_redirect(
                "https://attacker.example/phish", "default", self._request()
            )
        )

    def test_javascript_scheme_is_unsafe(self):
        self.assertFalse(
            is_safe_login_redirect(
                "javascript:alert(1)", "default", self._request()
            )
        )

    def test_protocol_relative_url_is_unsafe(self):
        self.assertFalse(
            is_safe_login_redirect(
                "//attacker.example/phish", "default", self._request()
            )
        )
