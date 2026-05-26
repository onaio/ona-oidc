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

User = get_user_model()

SSO_AUTH_CONFIG = {
    "JWT_SECRET_KEY": "test-secret-key-that-is-long-enough-to-be-ok",
    "JWT_ALGORITHM": "HS256",
}


def _make_sso_request(payload):
    """Build a request carrying a signed SSO cookie for ``payload``."""
    token = jwt.encode(
        payload,
        SSO_AUTH_CONFIG["JWT_SECRET_KEY"],
        SSO_AUTH_CONFIG["JWT_ALGORITHM"],
    )
    request = APIRequestFactory().get("/")
    request.COOKIES["SSO"] = token
    return request


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


class TestAuthenticateSSO(TestCase):
    """Tests for ``authenticate_sso`` SSO cookie/header resolution."""

    @override_settings(OPENID_CONNECT_VIEWSET_CONFIG=SSO_AUTH_CONFIG)
    def test_email_default_resolves_user(self):
        """With no SSO_COOKIE_DATA override, lookup falls back to email."""
        user = User.objects.create_user(
            username="alice", email="alice@example.com", is_active=True
        )
        request = _make_sso_request({"email": "alice@example.com"})
        self.assertEqual(authenticate_sso(request), (user, True))

    @override_settings(
        OPENID_CONNECT_VIEWSET_CONFIG={**SSO_AUTH_CONFIG, "SSO_COOKIE_DATA": "username"}
    )
    def test_resolves_correct_account_by_username_for_shared_email(self):
        """
        Two accounts sharing an email are disambiguated by the unique
        username claim instead of an arbitrary ``.first()`` pick.
        """
        User.objects.create_user(
            username="john", email="team@example.com", is_active=True
        )
        jane = User.objects.create_user(
            username="jane", email="team@example.com", is_active=True
        )
        request = _make_sso_request({"username": "jane"})
        self.assertEqual(authenticate_sso(request), (jane, True))

    @override_settings(
        OPENID_CONNECT_VIEWSET_CONFIG={**SSO_AUTH_CONFIG, "SSO_COOKIE_DATA": "username"}
    )
    def test_returns_none_when_configured_claim_missing(self):
        """A legacy cookie missing the configured claim must not match."""
        User.objects.create_user(
            username="bob", email="bob@example.com", is_active=True
        )
        request = _make_sso_request({"email": "bob@example.com"})
        self.assertIsNone(authenticate_sso(request))

    @override_settings(
        OPENID_CONNECT_VIEWSET_CONFIG={**SSO_AUTH_CONFIG, "SSO_COOKIE_DATA": "email"}
    )
    def test_explicit_field_argument_overrides_config(self):
        user = User.objects.create_user(
            username="carol", email="carol@example.com", is_active=True
        )
        request = _make_sso_request({"username": "carol"})
        self.assertEqual(
            authenticate_sso(request, unique_user_field="username"), (user, True)
        )

    @override_settings(
        OPENID_CONNECT_VIEWSET_CONFIG={**SSO_AUTH_CONFIG, "SSO_COOKIE_DATA": "username"}
    )
    def test_inactive_user_not_authenticated(self):
        User.objects.create_user(
            username="dave", email="dave@example.com", is_active=False
        )
        request = _make_sso_request({"username": "dave"})
        self.assertIsNone(authenticate_sso(request))

    @override_settings(OPENID_CONNECT_VIEWSET_CONFIG=SSO_AUTH_CONFIG)
    def test_returns_none_without_sso_token(self):
        request = APIRequestFactory().get("/")
        self.assertIsNone(authenticate_sso(request))

    @override_settings(OPENID_CONNECT_VIEWSET_CONFIG=SSO_AUTH_CONFIG)
    def test_malformed_token_fails_closed(self):
        """A malformed token returns None rather than raising."""
        request = APIRequestFactory().get("/")
        request.COOKIES["SSO"] = "not-a-jwt"
        self.assertIsNone(authenticate_sso(request))

    @override_settings(OPENID_CONNECT_VIEWSET_CONFIG=SSO_AUTH_CONFIG)
    def test_token_signed_with_wrong_key_fails_closed(self):
        """A token signed with the wrong secret returns None, not a 500."""
        User.objects.create_user(
            username="erin", email="erin@example.com", is_active=True
        )
        token = jwt.encode(
            {"email": "erin@example.com"},
            "a-different-secret-key-than-the-server-uses",
            "HS256",
        )
        request = APIRequestFactory().get("/")
        request.COOKIES["SSO"] = token
        self.assertIsNone(authenticate_sso(request))
