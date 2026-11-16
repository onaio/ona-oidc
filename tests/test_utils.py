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
    str_to_bool,
)
from tests.error_reports import escaped_frames, reported_locals


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

    @override_settings(
        OPENID_CONNECT_VIEWSET_CONFIG={"JWT_SECRET_KEY": "abc"}
    )
    def test_invalid_tokens_return_none_instead_of_raising(self):
        """Malformed or expired tokens are an authentication miss, not a 500."""
        tokens = {
            "malformed": "not-a-jwt",
            "expired": jwt.encode(
                {"email": "jdoe@example.com", "exp": 0}, "abc", algorithm="HS256"
            ),
        }
        for name, token in tokens.items():
            with self.subTest(name):
                self.assertIsNone(authenticate_sso(self._request(token)))

    @override_settings(
        OPENID_CONNECT_VIEWSET_CONFIG={"JWT_SECRET_KEY": "abc"}
    )
    def test_token_without_exp_is_rejected(self):
        """A token with no expiry is a forever-credential; refuse it."""
        token = jwt.encode({"email": "jdoe@example.com"}, "abc", algorithm="HS256")
        self.assertIsNone(authenticate_sso(self._request(token)))

    def test_missing_or_empty_secret_raises_improperly_configured(self):
        """A token can never be verified against a missing/empty secret."""
        token = jwt.encode({"email": "jdoe@example.com"}, "abc", algorithm="HS256")
        for config in ({}, {"JWT_SECRET_KEY": ""}):
            with self.subTest(config=config):
                with override_settings(OPENID_CONNECT_VIEWSET_CONFIG=config):
                    with self.assertRaises(ImproperlyConfigured):
                        authenticate_sso(self._request(token))

    def test_locals_hidden_from_error_reports(self):
        """
        An error from inside jwt.decode shows no signing key or cookie in error
        reports, in authenticate_sso's frame or in PyJWT's
        """
        # PyJWT refuses an SSH-key-shaped HMAC secret with InvalidKeyError,
        # which authenticate_sso lets escape.
        secret = "ssh-rsa s3cr3t-jwt-value"
        cookie = jwt.encode({"email": "jdoe@example.com"}, "abc", algorithm="HS256")
        request = self.factory.get("/", HTTP_SSO=cookie)

        with override_settings(
            OPENID_CONNECT_VIEWSET_CONFIG={"JWT_SECRET_KEY": secret}
        ):
            frames = escaped_frames(
                lambda: authenticate_sso(request),
                jwt.InvalidKeyError,
                "authenticate_sso",
            )

        self.assertTrue(any(f.f_locals.get("key") == secret for f in frames[1:]))
        self.assertIn("secret_key", reported_locals(frames[0]))
        for frame in frames:
            for value in (secret, cookie):
                self.assertNotIn(value, str(reported_locals(frame)))


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


class TestStrToBool(TestCase):
    def test_false_spellings_are_false(self):
        for val in ["False", "false", "FALSE", "0", "no", "off", " false "]:
            with self.subTest(val=val):
                self.assertIs(str_to_bool(val), False)

    def test_true_spellings_are_true(self):
        for val in ["True", "true", "TRUE", "1", "yes", "on", " true "]:
            with self.subTest(val=val):
                self.assertIs(str_to_bool(val), True)

    def test_non_strings_pass_through(self):
        for val in [True, False, None, 0, 1]:
            with self.subTest(val=val):
                self.assertIs(str_to_bool(val), val)

    def test_unrecognized_string_raises_improperly_configured(self):
        with self.assertRaises(ImproperlyConfigured):
            str_to_bool("flase")

    def test_blank_string_raises_improperly_configured(self):
        for val in ["", "   "]:
            with self.subTest(val=val):
                with self.assertRaises(ImproperlyConfigured):
                    str_to_bool(val)
