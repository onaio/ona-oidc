"""Tests for module oidc.utils"""

from django.contrib.auth import get_user_model
from django.core.exceptions import ImproperlyConfigured
from django.test import TestCase
from django.test.utils import override_settings

import jwt
from rest_framework.test import APIRequestFactory

from oidc.utils import (
    authenticate_sso,
    get_login_query_param_allowlist,
    is_safe_login_redirect,
)


class TestAuthenticateSSO(TestCase):
    """Tests for the public SSO verification entry point."""

    def setUp(self):
        self.factory = APIRequestFactory()
        self.user = get_user_model().objects.create(
            username="jdoe", email="jdoe@example.com", is_active=True
        )

    def _request(self, sso=None):
        request = self.factory.get("/")
        if sso is not None:
            request.COOKIES["SSO"] = sso
        return request

    def test_missing_or_empty_secret_raises_improperly_configured(self):
        """A token can never be verified against a missing/empty secret."""
        token = jwt.encode({"email": "jdoe@example.com"}, "abc", algorithm="HS256")
        for config in ({}, {"JWT_SECRET_KEY": ""}):
            with self.subTest(config=config):
                with override_settings(OPENID_CONNECT_VIEWSET_CONFIG=config):
                    with self.assertRaises(ImproperlyConfigured):
                        authenticate_sso(self._request(token))


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

    @override_settings(
        OPENID_CONNECT_AUTH_SERVERS={
            "default": {"LOGIN_QUERY_PARAM_ALLOWLIST": "prompt"},
        }
    )
    def test_string_misconfig_raises_improperly_configured(self):
        with self.assertRaises(ImproperlyConfigured):
            get_login_query_param_allowlist("default")


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

    @override_settings(
        OPENID_CONNECT_AUTH_SERVERS={
            "default": {"LOGIN_REDIRECT_ALLOWED_HOSTS": "spa.example.com"},
        }
    )
    def test_string_misconfig_raises_improperly_configured(self):
        with self.assertRaises(ImproperlyConfigured):
            is_safe_login_redirect(
                "https://spa.example.com/x", "default", self._request()
            )
