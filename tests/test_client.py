"""Tests for module oidc.client"""

import base64
import hashlib
import json
import secrets
import time
import traceback
from itertools import product
from unittest.mock import MagicMock, patch
from urllib.parse import quote, urlencode

from django.core import signing
from django.core.cache import cache
from django.core.exceptions import ImproperlyConfigured
from django.http import HttpResponseRedirect
from django.test import TestCase
from django.test.utils import override_settings

import jwt
import requests
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from jwt.algorithms import ECAlgorithm, RSAAlgorithm

from oidc.client import (
    LOGIN_BINDING_COOKIE_PREFIX,
    LOGIN_BINDING_MAX_AGE,
    LOGIN_BINDING_SLOTS,
    REDIRECT_AFTER_AUTH,
    REQUEST_MODES,
    NoJSONWebKeyFound,
    NonceVerificationFailed,
    OpenIDClient,
    TokenVerificationFailed,
    UserInfoRequestFailed,
    allocate_login_binding_slot,
    login_binding_cookie_names,
    login_binding_matches,
    matching_login_binding_cookie,
    seal_login_binding,
    stale_login_binding_cookies,
    state_cache_key,
)
from tests.error_reports import escaped_frames, reported_locals

OPENID_CONNECT_AUTH_SERVERS = {
    "default": {
        "AUTHORIZATION_ENDPOINT": "https://example.com/oauth2/v2.0/authorize",
        "CLIENT_ID": "client",
        "JWKS_ENDPOINT": "https://example.com/discovery/v2.0/keys",
        "SCOPE": "openid profile",
        "TOKEN_ENDPOINT": "https://example.com/oauth2/v2.0/token",
        "END_SESSION_ENDPOINT": "http://localhost:3000",
        "REDIRECT_URI": "http://localhost:8000/oidc/msft/callback",
        "RESPONSE_TYPE": "code",
        "RESPONSE_MODE": "form_post",
        "USE_NONCES": True,
        "NONCE_CACHE_TIMEOUT": 600,
    },
    "pkce": {
        "AUTHORIZATION_ENDPOINT": "https://example.com/oauth2/v2.0/authorize",
        "CLIENT_ID": "client",
        "CLIENT_SECRET": "client_secret",
        "JWKS_ENDPOINT": "https://example.com/discovery/v2.0/keys",
        "SCOPE": "openid profile",
        "TOKEN_ENDPOINT": "https://example.com/oauth2/v2.0/token",
        "END_SESSION_ENDPOINT": "http://localhost:3000",
        "REDIRECT_URI": "http://localhost:8000/oidc/msft/callback",
        "RESPONSE_TYPE": "code",
        "USE_NONCES": False,
        "RESPONSE_MODE": "form_post",
        "REQUEST_MODE": "form_post",
        "USE_PKCE": True,
        "PKCE_CODE_CHALLENGE_METHOD": "S256",
        "PKCE_CODE_CHALLENGE_TIMEOUT": 600,
        "PKCE_CODE_VERIFIER_LENGTH": 128,
    },
}

LEAKY_SECRET = "s3cr3t-value"
QUERY_MODE_AUTH_SERVERS = {
    "pkce": {
        **OPENID_CONNECT_AUTH_SERVERS["pkce"],
        "CLIENT_SECRET": LEAKY_SECRET,
        "REQUEST_MODE": "query",
    }
}


class OpenIDClientTestCase(TestCase):
    """Tests for class OpenIDClient"""

    def setUp(self) -> None:
        super().setUp()

        self.maxDiff = None
        cache.clear()

    @override_settings(OPENID_CONNECT_AUTH_SERVERS=OPENID_CONNECT_AUTH_SERVERS)
    @patch.object(cache, "set")
    @patch.object(secrets, "token_urlsafe")
    def test_login(self, mock_token_urlsafe, mock_cache_set):
        """Returns redirect URL"""
        mock_token_urlsafe.return_value = "123"
        expected_url = (
            "https://example.com/oauth2/v2.0/authorize?"
            "client_id=client&"
            "redirect_uri=http://localhost:8000/oidc/msft/callback&"
            "scope=openid%20profile&"
            "response_type=code&"
            "response_mode=form_post&"
            "state=123&"
            "nonce=123"
        )
        client = OpenIDClient("default")
        result = client.login()
        mock_cache_set.assert_called_once_with(
            "123",
            {"auth_server": "default", "redirect_after": None},
            600,
        )
        self.assertIsInstance(result, HttpResponseRedirect)
        self.assertEqual(result.url, expected_url)

        # `redirect_after` arg is passed
        mock_cache_set.reset_mock()
        result = client.login("foo")
        mock_cache_set.assert_called_once_with(
            "123",
            {"auth_server": "default", "redirect_after": "foo"},
            600,
        )
        self.assertIsInstance(result, HttpResponseRedirect)
        self.assertEqual(result.url, expected_url)

    @override_settings(OPENID_CONNECT_AUTH_SERVERS=OPENID_CONNECT_AUTH_SERVERS)
    @patch.object(cache, "set")
    @patch.object(secrets, "token_urlsafe")
    def test_login_always_carries_state(self, mock_token_urlsafe, _mock_cache_set):
        """Every login URL carries a state value, with or without PKCE.

        The callback can only bind an authorization response to the
        browser that started the login if the IdP echoes a state value
        back, so a flow without state could never be bound.
        """
        mock_token_urlsafe.return_value = "123"
        for auth_server in ("default", "pkce"):
            with self.subTest(auth_server=auth_server):
                result_url = OpenIDClient(auth_server).login().url
                self.assertIn("state=123", result_url)

    @override_settings(OPENID_CONNECT_AUTH_SERVERS=OPENID_CONNECT_AUTH_SERVERS)
    def test_login_redirect_is_never_cached(self):
        """The login redirect declares no-store.

        The redirect carries a per-browser state (and Set-Cookie), so a
        shared cache replaying it would hand the same login attempt to
        several browsers.
        """
        response = OpenIDClient("default").login()
        self.assertEqual(response["Cache-Control"], "no-store")

    @override_settings(OPENID_CONNECT_AUTH_SERVERS=OPENID_CONNECT_AUTH_SERVERS)
    @patch.object(cache, "set")
    @patch.object(secrets, "token_urlsafe")
    def test_login_forwards_extra_params(self, mock_token_urlsafe, mock_cache_set):
        mock_token_urlsafe.return_value = "123"
        client = OpenIDClient("default")

        result = client.login(
            extra_params={
                "kc_idp_hint": "onadata",
                "login_hint": "alice@example.com",
                "prompt": "login",
            }
        )

        expected_url = (
            "https://example.com/oauth2/v2.0/authorize?"
            "client_id=client&"
            "redirect_uri=http://localhost:8000/oidc/msft/callback&"
            "scope=openid%20profile&"
            "response_type=code&"
            "response_mode=form_post&"
            "kc_idp_hint=onadata&"
            "login_hint=alice%40example.com&"
            "prompt=login&"
            "state=123&"
            "nonce=123"
        )
        self.assertIsInstance(result, HttpResponseRedirect)
        self.assertEqual(result.url, expected_url)
        mock_cache_set.assert_called_once_with(
            "123",
            {"auth_server": "default", "redirect_after": None},
            600,
        )

    @override_settings(OPENID_CONNECT_AUTH_SERVERS=OPENID_CONNECT_AUTH_SERVERS)
    @patch.object(secrets, "token_urlsafe")
    def test_login_no_extra_params_keeps_url_clean(self, mock_token_urlsafe):
        mock_token_urlsafe.return_value = "123"
        client = OpenIDClient("default")

        unchanged_tail = "response_mode=form_post&state=123&nonce=123"

        self.assertTrue(client.login(extra_params=None).url.endswith(unchanged_tail))
        self.assertTrue(client.login(extra_params={}).url.endswith(unchanged_tail))

    @override_settings(OPENID_CONNECT_AUTH_SERVERS=OPENID_CONNECT_AUTH_SERVERS)
    @patch.object(cache, "set")
    @patch.object(secrets, "token_urlsafe")
    def test_login_drops_reserved_authorize_params(
        self, mock_token_urlsafe, _mock_cache_set
    ):
        mock_token_urlsafe.return_value = "123"
        client = OpenIDClient("default")

        result_url = client.login(
            extra_params={
                "client_id": "evil",
                "redirect_uri": "https://attacker.example/cb",
                "state": "spoofed",
                "nonce": "spoofed",
                "code_challenge": "spoofed",
                "code_challenge_method": "plain",
                "request": "ey.attacker.signed.jwt",
                "request_uri": "https://attacker.example/req.jwt",
                "registration": '{"redirect_uris": ["https://attacker.example/cb"]}',
                "client_metadata": '{"redirect_uris": ["https://attacker.example/cb"]}',
                "client_metadata_uri": "https://attacker.example/metadata.json",
                "kc_idp_hint": "onadata",
            }
        ).url

        expected_url = (
            "https://example.com/oauth2/v2.0/authorize?"
            "client_id=client&"
            "redirect_uri=http://localhost:8000/oidc/msft/callback&"
            "scope=openid%20profile&"
            "response_type=code&"
            "response_mode=form_post&"
            "kc_idp_hint=onadata&"
            "state=123&"
            "nonce=123"
        )
        self.assertEqual(result_url, expected_url)

    @override_settings(OPENID_CONNECT_AUTH_SERVERS=OPENID_CONNECT_AUTH_SERVERS)
    @patch.object(cache, "set")
    @patch.object(secrets, "token_urlsafe")
    def test_login_extras_pkce_and_nonce_param_ordering(
        self, mock_token_urlsafe, _mock_cache_set
    ):
        mock_token_urlsafe.return_value = "123"
        code_verifier_hash = hashlib.sha256("123".encode("ascii")).digest()
        code_challenge = (
            base64.urlsafe_b64encode(code_verifier_hash).rstrip(b"=").decode("ascii")
        )
        client = OpenIDClient("pkce")

        result_url = client.login(
            redirect_after="/dashboard",
            extra_params={"kc_idp_hint": "onadata"},
        ).url

        expected_url = (
            "https://example.com/oauth2/v2.0/authorize?"
            "client_id=client&"
            "redirect_uri=http://localhost:8000/oidc/msft/callback&"
            "scope=openid%20profile&"
            "response_type=code&"
            "response_mode=form_post&"
            "kc_idp_hint=onadata&"
            f"code_challenge={code_challenge}&"
            "code_challenge_method=S256&"
            "state=123&"
            "nonce=123"
        )
        self.assertEqual(result_url, expected_url)

    @override_settings(OPENID_CONNECT_AUTH_SERVERS=OPENID_CONNECT_AUTH_SERVERS)
    @patch.object(cache, "set")
    @patch.object(secrets, "token_urlsafe")
    def test_login_non_ascii_extra_params(
        self, mock_token_urlsafe, _mock_cache_set
    ):
        mock_token_urlsafe.return_value = "123"
        client = OpenIDClient("default")

        result_url = client.login(
            extra_params={"login_hint": "ümlaut@example.com"}
        ).url

        # UTF-8 bytes for ``ü`` percent-encoded as ``%C3%BC``
        self.assertIn("login_hint=%C3%BCmlaut%40example.com", result_url)

    @override_settings(OPENID_CONNECT_AUTH_SERVERS=OPENID_CONNECT_AUTH_SERVERS)
    def test_logout_forwards_extra_params(self):
        """``extra_params`` are URL-encoded onto the end-session URL."""
        client = OpenIDClient("default")

        result = client.logout(
            extra_params={
                "id_token_hint": "ey.signed.jwt",
                "logout_hint": "alice@example.com",
                "ui_locales": "en-GB",
            }
        )

        self.assertIsInstance(result, HttpResponseRedirect)
        self.assertEqual(
            result.url,
            "http://localhost:3000?"
            "id_token_hint=ey.signed.jwt&"
            "logout_hint=alice%40example.com&"
            "ui_locales=en-GB",
        )

    @override_settings(
        OPENID_CONNECT_AUTH_SERVERS={
            "default": {
                **OPENID_CONNECT_AUTH_SERVERS["default"],
                # End-session URL with `client_id` + `post_logout_redirect_uri`
                # already baked in, the way Keycloak deployments typically
                # configure it.
                "END_SESSION_ENDPOINT": (
                    "https://idp.example.com/logout?"
                    "client_id=client&post_logout_redirect_uri=https%3A%2F%2Fapp%2F"
                ),
            }
        }
    )
    def test_logout_appends_with_ampersand_when_endpoint_has_query(self):
        """When END_SESSION_ENDPOINT already carries a query string, the
        separator switches from ``?`` to ``&`` so the URL stays valid."""
        client = OpenIDClient("default")

        result_url = client.logout(
            extra_params={"id_token_hint": "ey.signed.jwt"}
        ).url

        self.assertEqual(
            result_url,
            "https://idp.example.com/logout?"
            "client_id=client&post_logout_redirect_uri=https%3A%2F%2Fapp%2F&"
            "id_token_hint=ey.signed.jwt",
        )

    @override_settings(OPENID_CONNECT_AUTH_SERVERS=OPENID_CONNECT_AUTH_SERVERS)
    def test_logout_no_extra_params_keeps_url_clean(self):
        """``None`` / ``{}`` / all-reserved leave the URL untouched."""
        client = OpenIDClient("default")

        self.assertEqual(client.logout().url, "http://localhost:3000")
        self.assertEqual(client.logout(extra_params=None).url, "http://localhost:3000")
        self.assertEqual(client.logout(extra_params={}).url, "http://localhost:3000")
        # All entries reserved → filtered to empty → no stray `?`.
        self.assertEqual(
            client.logout(
                extra_params={
                    "client_id": "evil",
                    "post_logout_redirect_uri": "https://attacker.example/",
                }
            ).url,
            "http://localhost:3000",
        )

    @override_settings(OPENID_CONNECT_AUTH_SERVERS=OPENID_CONNECT_AUTH_SERVERS)
    def test_logout_drops_reserved_end_session_params(self):
        """Caller-supplied ``client_id`` / ``post_logout_redirect_uri`` are
        filtered at the client boundary — the security guard mirrors
        ``RESERVED_AUTHORIZE_PARAMS`` on the login side."""
        client = OpenIDClient("default")

        result_url = client.logout(
            extra_params={
                "client_id": "evil",
                "post_logout_redirect_uri": "https://attacker.example/cb",
                "id_token_hint": "ey.signed.jwt",
            }
        ).url

        self.assertEqual(
            result_url,
            "http://localhost:3000?id_token_hint=ey.signed.jwt",
        )

    @override_settings(
        OPENID_CONNECT_AUTH_SERVERS={
            "default": {
                "AUTHORIZATION_ENDPOINT": "https://example.com/oauth2/v2.0/authorize",
                "CLIENT_ID": "client",
                "JWKS_ENDPOINT": "https://example.com/discovery/v2.0/keys",
                "SCOPE": "openid profile",
                "TOKEN_ENDPOINT": "https://example.com/oauth2/v2.0/token",
                "END_SESSION_ENDPOINT": "http://localhost:3000",
                "REDIRECT_URI": "http://localhost:8000/oidc/msft/callback",
                "RESPONSE_TYPE": "code",
                "RESPONSE_MODE": "form_post",
                "USE_NONCES": True,
            }
        }
    )
    @patch.object(cache, "set")
    @patch.object(secrets, "token_urlsafe")
    def test_login_nonce_timeout_missing(self, mock_token_urlsafe, mock_cache_set):
        """Uses default nonce timeout on login if timeout not set"""
        mock_token_urlsafe.return_value = "123"
        expected_url = (
            "https://example.com/oauth2/v2.0/authorize?"
            "client_id=client&"
            "redirect_uri=http://localhost:8000/oidc/msft/callback&"
            "scope=openid%20profile&"
            "response_type=code&"
            "response_mode=form_post&"
            "state=123&"
            "nonce=123"
        )
        client = OpenIDClient("default")
        result = client.login()
        mock_cache_set.assert_called_once_with(
            "123",
            {"auth_server": "default", "redirect_after": None},
            1800,
        )
        self.assertIsInstance(result, HttpResponseRedirect)
        self.assertEqual(result.url, expected_url)

    @override_settings(OPENID_CONNECT_AUTH_SERVERS=OPENID_CONNECT_AUTH_SERVERS)
    @patch.object(cache, "set")
    @patch.object(secrets, "token_urlsafe")
    def test_login_pkce(self, mock_token_urlsafe, mock_cache_set):
        """Returns correct redirect URL for PKCE flow"""
        mock_token_urlsafe.return_value = "123"
        code_verifier_hash = hashlib.sha256(b"123").digest()
        expected_challenge = (
            base64.urlsafe_b64encode(code_verifier_hash).rstrip(b"=").decode("ascii")
        )
        expected_url = (
            "https://example.com/oauth2/v2.0/authorize?"
            "client_id=client&"
            "redirect_uri=http://localhost:8000/oidc/msft/callback&"
            "scope=openid%20profile&"
            "response_type=code&"
            "response_mode=form_post&"
            f"code_challenge={expected_challenge}&"
            "code_challenge_method=S256&"
            "state=123"
        )
        client = OpenIDClient("pkce")
        result = client.login()
        self.assertIsInstance(result, HttpResponseRedirect)
        self.assertEqual(result.url, expected_url)
        mock_cache_set.assert_called_once_with(state_cache_key("123"), "123", 600)
        # Two calls now: 128-byte verifier + 32-byte state.
        mock_token_urlsafe.assert_any_call(128)
        mock_token_urlsafe.assert_any_call(32)

    @override_settings(
        OPENID_CONNECT_AUTH_SERVERS={
            "pkce": {
                "AUTHORIZATION_ENDPOINT": "https://example.com/oauth2/v2.0/authorize",
                "CLIENT_ID": "client",
                "JWKS_ENDPOINT": "https://example.com/discovery/v2.0/keys",
                "SCOPE": "openid profile",
                "TOKEN_ENDPOINT": "https://example.com/oauth2/v2.0/token",
                "END_SESSION_ENDPOINT": "http://localhost:3000",
                "REDIRECT_URI": "http://localhost:8000/oidc/msft/callback",
                "RESPONSE_TYPE": "code",
                "USE_NONCES": False,
                "RESPONSE_MODE": "form_post",
                "USE_PKCE": True,
                "PKCE_CODE_CHALLENGE_METHOD": "S256",
                "PKCE_CODE_CHALLENGE_TIMEOUT": 600,
            }
        }
    )
    @patch.object(secrets, "token_urlsafe")
    def test_login_pkce_default_code_verifier_length(self, mock_token_urlsafe):
        """Uses default PKCE code verifier length on login if length not set"""
        mock_token_urlsafe.return_value = "123"
        code_verifier_hash = hashlib.sha256(b"123").digest()
        expected_challenge = (
            base64.urlsafe_b64encode(code_verifier_hash).rstrip(b"=").decode("ascii")
        )
        expected_url = (
            "https://example.com/oauth2/v2.0/authorize?"
            "client_id=client&"
            "redirect_uri=http://localhost:8000/oidc/msft/callback&"
            "scope=openid%20profile&"
            "response_type=code&"
            "response_mode=form_post&"
            f"code_challenge={expected_challenge}&"
            "code_challenge_method=S256&"
            "state=123"
        )
        client = OpenIDClient("pkce")
        result = client.login()
        self.assertIsInstance(result, HttpResponseRedirect)
        self.assertEqual(result.url, expected_url)
        # Default code verifier length is 64; state generation requests 32.
        mock_token_urlsafe.assert_any_call(64)
        mock_token_urlsafe.assert_any_call(32)

    @override_settings(
        OPENID_CONNECT_AUTH_SERVERS={
            "pkce": {
                "AUTHORIZATION_ENDPOINT": "https://example.com/oauth2/v2.0/authorize",
                "CLIENT_ID": "client",
                "JWKS_ENDPOINT": "https://example.com/discovery/v2.0/keys",
                "SCOPE": "openid profile",
                "TOKEN_ENDPOINT": "https://example.com/oauth2/v2.0/token",
                "END_SESSION_ENDPOINT": "http://localhost:3000",
                "REDIRECT_URI": "http://localhost:8000/oidc/msft/callback",
                "RESPONSE_TYPE": "code",
                "USE_NONCES": False,
                "RESPONSE_MODE": "form_post",
                "USE_PKCE": True,
                "PKCE_CODE_CHALLENGE_METHOD": "S256",
                "PKCE_CODE_VERIFIER_LENGTH": 128,
            }
        }
    )
    @patch.object(cache, "set")
    @patch.object(secrets, "token_urlsafe")
    def test_login_default_pkce_code_challenge_timeout(
        self, mock_token_urlsafe, mock_cache_set
    ):
        """Uses default PKCE code challenge timeout on login if timeout not set"""
        mock_token_urlsafe.return_value = "123"
        code_verifier_hash = hashlib.sha256(b"123").digest()
        expected_challenge = (
            base64.urlsafe_b64encode(code_verifier_hash).rstrip(b"=").decode("ascii")
        )
        expected_url = (
            "https://example.com/oauth2/v2.0/authorize?"
            "client_id=client&"
            "redirect_uri=http://localhost:8000/oidc/msft/callback&"
            "scope=openid%20profile&"
            "response_type=code&"
            "response_mode=form_post&"
            f"code_challenge={expected_challenge}&"
            "code_challenge_method=S256&"
            "state=123"
        )
        client = OpenIDClient("pkce")
        result = client.login()
        self.assertIsInstance(result, HttpResponseRedirect)
        self.assertEqual(result.url, expected_url)
        # Default code challenge timeout is 600
        mock_cache_set.assert_called_once_with(state_cache_key("123"), "123", 600)

    @override_settings(
        OPENID_CONNECT_AUTH_SERVERS={
            "pkce": {
                "AUTHORIZATION_ENDPOINT": "https://example.com/oauth2/v2.0/authorize",
                "CLIENT_ID": "client",
                "JWKS_ENDPOINT": "https://example.com/discovery/v2.0/keys",
                "SCOPE": "openid profile",
                "TOKEN_ENDPOINT": "https://example.com/oauth2/v2.0/token",
                "END_SESSION_ENDPOINT": "http://localhost:3000",
                "REDIRECT_URI": "http://localhost:8000/oidc/msft/callback",
                "RESPONSE_TYPE": "code",
                "USE_NONCES": False,
                "RESPONSE_MODE": "form_post",
                "USE_PKCE": True,
                "PKCE_CODE_CHALLENGE_TIMEOUT": 600,
                "PKCE_CODE_VERIFIER_LENGTH": 128,
            }
        }
    )
    @patch.object(secrets, "token_urlsafe")
    def test_login_pkce_default_pkce_code_challenge_method(self, mock_token_urlsafe):
        """Uses default PKCE code challenge method on login if method not set"""
        mock_token_urlsafe.return_value = "123"
        code_verifier_hash = hashlib.sha256(b"123").digest()
        expected_challenge = (
            base64.urlsafe_b64encode(code_verifier_hash).rstrip(b"=").decode("ascii")
        )
        expected_url = (
            "https://example.com/oauth2/v2.0/authorize?"
            "client_id=client&"
            "redirect_uri=http://localhost:8000/oidc/msft/callback&"
            "scope=openid%20profile&"
            "response_type=code&"
            "response_mode=form_post&"
            f"code_challenge={expected_challenge}&"
            "code_challenge_method=S256&"  # Default code challenge method is S256
            "state=123"
        )
        client = OpenIDClient("pkce")
        result = client.login()
        self.assertIsInstance(result, HttpResponseRedirect)
        self.assertEqual(result.url, expected_url)

    @override_settings(OPENID_CONNECT_AUTH_SERVERS=OPENID_CONNECT_AUTH_SERVERS)
    @patch.object(requests, "post")
    def test_retrieve_tokens_using_auth_code_pkce_flow_form_post(
        self, mock_requests_post
    ):
        """Retrieves tokens using the Authorization Code + PKCE flow with form_post"""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "id_token": "id_token",
            "access_token": "access_token",
            "refresh_token": "refresh_token",
        }
        mock_requests_post.return_value = mock_response

        client = OpenIDClient("pkce")
        result = client.retrieve_tokens_using_auth_code("auth_code", "123")

        self.assertEqual(
            result,
            {
                "id_token": "id_token",
                "access_token": "access_token",
                "refresh_token": "refresh_token",
            },
        )
        # Data is sent in the request body
        mock_requests_post.assert_called_once_with(
            "https://example.com/oauth2/v2.0/token",
            data={
                "grant_type": "authorization_code",
                "code": "auth_code",
                "client_id": "client",
                "client_secret": "client_secret",
                "redirect_uri": "http://localhost:8000/oidc/msft/callback",
                "code_verifier": "123",
            },
            params=None,
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            timeout=(5, 30),
        )

    @override_settings(
        OPENID_CONNECT_AUTH_SERVERS={
            "pkce": {
                **OPENID_CONNECT_AUTH_SERVERS["pkce"],
                "REQUEST_MODE": "query",
            }
        }
    )
    @patch.object(requests, "post")
    def test_retrieve_tokens_using_auth_code_pkce_flow_query(self, mock_requests_post):
        """Retrieves tokens using the Authorization Code + PKCE flow with query"""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "id_token": "id_token",
            "access_token": "access_token",
            "refresh_token": "refresh_token",
        }
        mock_requests_post.return_value = mock_response

        client = OpenIDClient("pkce")
        result = client.retrieve_tokens_using_auth_code("auth_code", "123")

        self.assertEqual(
            result,
            {
                "id_token": "id_token",
                "access_token": "access_token",
                "refresh_token": "refresh_token",
            },
        )
        # Data is sent in the query string
        mock_requests_post.assert_called_once_with(
            "https://example.com/oauth2/v2.0/token",
            data=None,
            params={
                "grant_type": "authorization_code",
                "code": "auth_code",
                "client_id": "client",
                "client_secret": "client_secret",
                "redirect_uri": "http://localhost:8000/oidc/msft/callback",
                "code_verifier": "123",
            },
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            timeout=(5, 30),
        )

    def test_unknown_request_mode_is_rejected(self):
        """A REQUEST_MODE other than form_post or query fails at construction"""

        def client_with(mode):
            server = {**OPENID_CONNECT_AUTH_SERVERS["pkce"], "REQUEST_MODE": mode}
            with override_settings(OPENID_CONNECT_AUTH_SERVERS={"pkce": server}):
                return OpenIDClient("pkce")

        for mode in ("form_post", "query"):
            with self.subTest(mode):
                self.assertEqual(client_with(mode).request_mode, mode)

        for mode in ("post", "FORM_POST", " form_post"):
            with self.subTest(mode):
                with self.assertRaisesMessage(ImproperlyConfigured, repr(mode)):
                    client_with(mode)

    def test_requests_timeout_setting(self):
        """``REQUESTS_TIMEOUT`` defaults to ``(5, 30)``. It takes a positive
        number or a pair of them, and anything else fails at construction."""

        def client_with(**extra):
            server = {**OPENID_CONNECT_AUTH_SERVERS["pkce"], **extra}
            with override_settings(OPENID_CONNECT_AUTH_SERVERS={"pkce": server}):
                return OpenIDClient("pkce")

        self.assertEqual(client_with().requests_timeout, (5, 30))
        for value, expected in (
            (10, 10),
            (2.5, 2.5),
            ((3, 60), (3, 60)),
            ([3, 60], (3, 60)),
        ):
            with self.subTest(value=value):
                timeout = client_with(REQUESTS_TIMEOUT=value).requests_timeout
                self.assertEqual(timeout, expected)

        for value in (None, 0, -1, True, "30", (5,), (5, 0), (5, None), (1, 2, 3)):
            with self.subTest(value=value):
                with self.assertRaisesMessage(ImproperlyConfigured, "REQUESTS_TIMEOUT"):
                    client_with(REQUESTS_TIMEOUT=value)

    def test_non_positive_nonce_cache_timeout_is_rejected(self):
        """Django's cache treats a timeout of 0 or less as already expired,
        so the username form could never be submitted."""

        def client_with(timeout):
            server = {
                **OPENID_CONNECT_AUTH_SERVERS["default"],
                "NONCE_CACHE_TIMEOUT": timeout,
            }
            with override_settings(OPENID_CONNECT_AUTH_SERVERS={"default": server}):
                return OpenIDClient("default")

        self.assertEqual(client_with(1).nonce_cache_timeout, 1)
        for timeout in (0, -1, "0"):
            with self.subTest(timeout=timeout):
                with self.assertRaisesMessage(
                    ImproperlyConfigured, "NONCE_CACHE_TIMEOUT"
                ):
                    client_with(timeout)

    @override_settings(
        OPENID_CONNECT_AUTH_SERVERS={
            "default": {
                **OPENID_CONNECT_AUTH_SERVERS["default"],
                "CLIENT_SECRET": "client_secret",
            }
        }
    )
    @patch.object(requests, "post")
    def test_retrieve_tokens_using_auth_code_defaults_to_form_post(
        self, mock_requests_post
    ):
        """Without REQUEST_MODE, credentials go in the request body, not the URL"""
        self.assertNotIn("REQUEST_MODE", OPENID_CONNECT_AUTH_SERVERS["default"])
        mock_requests_post.return_value = MagicMock(
            status_code=200, **{"json.return_value": {"id_token": "id_token"}}
        )

        result = OpenIDClient("default").retrieve_tokens_using_auth_code("auth_code")

        self.assertEqual(result, {"id_token": "id_token"})

        mock_requests_post.assert_called_once_with(
            "https://example.com/oauth2/v2.0/token",
            data={
                "grant_type": "authorization_code",
                "code": "auth_code",
                "client_id": "client",
                "client_secret": "client_secret",
                "redirect_uri": "http://localhost:8000/oidc/msft/callback",
            },
            params=None,
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            timeout=(5, 30),
        )

    def _assert_secret_not_exposed(self, mock_requests_post, logs, raised):
        # Only query mode puts the secret in the URL. Without it, the checks
        # below cannot fail.
        self.assertIn(
            LEAKY_SECRET, mock_requests_post.call_args.kwargs["params"].values()
        )
        self.assertTrue(all(record.exc_info is None for record in logs.records))
        self.assertNotIn(LEAKY_SECRET, "\n".join(logs.output))
        reported = [getattr(r, "token_response", {}) for r in logs.records]
        self.assertNotIn(LEAKY_SECRET, str(reported))
        formatted = "".join(
            traceback.format_exception(type(raised), raised, raised.__traceback__)
        )
        self.assertNotIn(LEAKY_SECRET, formatted)

    def _token_response(self, status_code, content, content_type=None):
        response = requests.Response()
        response.status_code = status_code
        if content_type:
            response.headers["Content-Type"] = content_type
        response.reason = "Error"
        response.url = (
            f"https://example.com/oauth2/v2.0/token?client_secret={LEAKY_SECRET}"
        )
        response._content = content
        return response

    def _retrieve_tokens_expecting_failure(self):
        with self.assertLogs("oidc.client", level="DEBUG") as logs:
            with self.assertRaises(TokenVerificationFailed) as raised:
                OpenIDClient("pkce").retrieve_tokens_using_auth_code("auth_code")
        return "\n".join(logs.output), logs, raised.exception

    @override_settings(OPENID_CONNECT_AUTH_SERVERS=QUERY_MODE_AUTH_SERVERS)
    @patch.object(requests, "post")
    def test_retrieve_tokens_error_response_hides_client_secret(
        self, mock_requests_post
    ):
        """A rejected token request logs its status, never the secret"""
        cases = {
            "provider error": (
                400,
                json.dumps(
                    {
                        "error": "invalid_request",
                        "error_description": "Sensitive data in the URL.",
                    }
                ).encode(),
                "HTTP 400",
            ),
            "html error page": (502, b"<html>Bad Gateway</html>", "HTTP 502"),
        }
        for name, (status_code, body, expected_log) in cases.items():
            with self.subTest(name):
                mock_requests_post.return_value = self._token_response(
                    status_code, body
                )

                logged, logs, raised = self._retrieve_tokens_expecting_failure()

                self.assertIn(expected_log, logged)
                self.assertNotIn("HTTPError", logged)
                self._assert_secret_not_exposed(mock_requests_post, logs, raised)

    @override_settings(OPENID_CONNECT_AUTH_SERVERS=QUERY_MODE_AUTH_SERVERS)
    @patch.object(requests, "post")
    def test_retrieve_tokens_locals_hidden_from_error_reports(self, mock_requests_post):
        """An unexpected error from the exchange shows no credentials in error reports"""
        code, verifier = "c0de-value", "v3rifier-value"
        mock_requests_post.side_effect = RuntimeError("unexpected")

        frames = escaped_frames(
            lambda: OpenIDClient("pkce").retrieve_tokens_using_auth_code(
                code, verifier
            ),
            RuntimeError,
            "retrieve_tokens_using_auth_code",
        )

        self.assertIn(LEAKY_SECRET, str(frames[0].f_locals["data"]))
        self.assertIn("data", reported_locals(frames[0]))
        for frame in frames:
            for value in (LEAKY_SECRET, code, verifier):
                self.assertNotIn(value, str(reported_locals(frame)))

    @override_settings(OPENID_CONNECT_AUTH_SERVERS=QUERY_MODE_AUTH_SERVERS)
    @patch.object(requests, "post")
    def test_retrieve_tokens_connection_error_hides_client_secret(
        self, mock_requests_post
    ):
        """A token request that never gets a response does not leak the secret"""
        mock_requests_post.side_effect = requests.ConnectionError(
            "HTTPSConnectionPool(host='example.com', port=443): Max retries "
            f"exceeded with url: /oauth2/v2.0/token?client_secret={LEAKY_SECRET}"
        )

        logged, logs, raised = self._retrieve_tokens_expecting_failure()

        self.assertIn("ConnectionError", logged)
        self.assertFalse(hasattr(logs.records[0], "token_response"))
        self._assert_secret_not_exposed(mock_requests_post, logs, raised)

    @patch.object(requests, "post")
    def test_retrieve_tokens_failure_omits_encoded_echo(self, mock_requests_post):
        """
        A provider that echoes the secret back leaks nothing, whatever the
        encoding. The report has the response metadata, never the body.
        """
        cases = {
            "form-encoded": (
                "dummy secret",
                urlencode({"client_secret": "dummy secret"}),
                "dummy+secret",
                "application/x-www-form-urlencoded",
            ),
            "json-escaped": (
                'dummy"secret',
                json.dumps({"error_description": 'dummy"secret'}),
                'dummy\\"secret',
                "application/json",
            ),
        }
        for (name, case), mode in product(cases.items(), REQUEST_MODES):
            secret, body, echoed, content_type = case
            # The echo must dodge a plain or percent-encoded match of the secret.
            self.assertIn(echoed, body)
            self.assertNotIn(secret, body)
            self.assertNotIn(quote(secret, safe=""), body)
            server = {
                **QUERY_MODE_AUTH_SERVERS["pkce"],
                "CLIENT_SECRET": secret,
                "REQUEST_MODE": mode,
            }
            mock_requests_post.return_value = self._token_response(
                400, body.encode(), content_type
            )
            with self.subTest(name, mode=mode):
                with (
                    override_settings(OPENID_CONNECT_AUTH_SERVERS={"pkce": server}),
                    self.assertLogs("oidc.client", level="DEBUG") as logs,
                    self.assertRaises(TokenVerificationFailed),
                ):
                    OpenIDClient("pkce").retrieve_tokens_using_auth_code("auth_code")

                record = logs.records[0]
                self.assertIn("HTTP 400", record.getMessage())
                self.assertEqual(
                    record.token_response,
                    {
                        "status_code": 400,
                        "content_type": content_type,
                        "body_length": len(body),
                    },
                )

    @override_settings(OPENID_CONNECT_AUTH_SERVERS=QUERY_MODE_AUTH_SERVERS)
    @patch.object(requests, "post")
    def test_retrieve_tokens_success_without_token_object_raises(
        self, mock_requests_post
    ):
        """A 200 whose body is not a JSON object is a handled failure"""
        cases = {
            "not json": (b"<html>Gateway login</html>", "HTTP 200 JSONDecodeError"),
            "json list": (b'["id_token"]', "HTTP 200 non-object JSON"),
        }
        for name, (body, expected_log) in cases.items():
            with self.subTest(name):
                mock_requests_post.return_value = self._token_response(200, body)

                logged, _logs, _raised = self._retrieve_tokens_expecting_failure()

                self.assertIn(expected_log, logged)

    @override_settings(
        OPENID_CONNECT_AUTH_SERVERS={
            "default": {
                **OPENID_CONNECT_AUTH_SERVERS["default"],
                "USER_INFO_ENDPOINT": "https://example.com/oauth2/userinfo",
            }
        }
    )
    @patch.object(requests, "get")
    def test_retrieve_user_info(self, mock_requests_get):
        """Retrieves user profile claims using access token"""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "sub": "1234567890",
            "email": "user@example.com",
            "name": "John Doe",
        }
        mock_requests_get.return_value = mock_response

        client = OpenIDClient("default")
        result = client.retrieve_user_info("access_token_value")

        self.assertEqual(
            result,
            {"sub": "1234567890", "email": "user@example.com", "name": "John Doe"},
        )
        mock_requests_get.assert_called_once_with(
            "https://example.com/oauth2/userinfo",
            headers={"Authorization": "Bearer access_token_value"},
            timeout=(5, 30),
        )

    @override_settings(
        OPENID_CONNECT_AUTH_SERVERS={
            "default": {
                **OPENID_CONNECT_AUTH_SERVERS["default"],
                "USER_INFO_ENDPOINT": "https://example.com/oauth2/userinfo",
            }
        }
    )
    @patch.object(requests, "get")
    def test_failed_user_info_request_raises(self, mock_requests_get):
        """A userinfo request that fails, gets an error status or gets a
        body that is not JSON raises ``UserInfoRequestFailed``. The reason
        names no URL or token."""
        not_json = MagicMock(status_code=200)
        not_json.json.side_effect = ValueError("Expecting value")
        cases = {
            "Userinfo request failed: Timeout": {
                "side_effect": requests.Timeout(
                    "https://example.com/oauth2/userinfo timed out"
                )
            },
            "Userinfo request failed: status 401": {
                "return_value": MagicMock(status_code=401)
            },
            "Userinfo response is not JSON": {"return_value": not_json},
        }
        for reason, outcome in cases.items():
            with self.subTest(reason):
                mock_requests_get.configure_mock(
                    **{"side_effect": None, "return_value": None, **outcome}
                )
                with self.assertRaises(UserInfoRequestFailed) as ctx:
                    OpenIDClient("default").retrieve_user_info("access_token_value")
                self.assertEqual(str(ctx.exception), reason)

    @override_settings(OPENID_CONNECT_AUTH_SERVERS=OPENID_CONNECT_AUTH_SERVERS)
    @patch.object(requests, "get")
    def test_failed_jwks_request_raises_no_jwk_found(self, mock_requests_get):
        """A JWKS request that times out is a signing-key failure, which the
        callback turns into a 401. The reason names no URL."""
        mock_requests_get.side_effect = requests.Timeout(
            "https://example.com/discovery/v2.0/keys timed out"
        )

        with self.assertRaises(NoJSONWebKeyFound) as ctx:
            OpenIDClient("default")._retrieve_jwks_related_to_kid("kid")

        self.assertEqual(str(ctx.exception), "JWKS request failed: Timeout")
        mock_requests_get.assert_called_once_with(
            "https://example.com/discovery/v2.0/keys", timeout=(5, 30)
        )

    @override_settings(OPENID_CONNECT_AUTH_SERVERS=OPENID_CONNECT_AUTH_SERVERS)
    def test_get_hash_algorithm(self):
        """Maps JWT algorithms to correct hash functions"""
        client = OpenIDClient("default")

        # Test RS algorithms
        self.assertEqual(client.get_hash_algorithm("RS256"), hashlib.sha256)
        self.assertEqual(client.get_hash_algorithm("RS384"), hashlib.sha384)
        self.assertEqual(client.get_hash_algorithm("RS512"), hashlib.sha512)

        # Test ES algorithms
        self.assertEqual(client.get_hash_algorithm("ES256"), hashlib.sha256)
        self.assertEqual(client.get_hash_algorithm("ES384"), hashlib.sha384)
        self.assertEqual(client.get_hash_algorithm("ES512"), hashlib.sha512)

        # Test PS algorithms
        self.assertEqual(client.get_hash_algorithm("PS256"), hashlib.sha256)
        self.assertEqual(client.get_hash_algorithm("PS384"), hashlib.sha384)
        self.assertEqual(client.get_hash_algorithm("PS512"), hashlib.sha512)

        # Test HS algorithms
        self.assertEqual(client.get_hash_algorithm("HS256"), hashlib.sha256)
        self.assertEqual(client.get_hash_algorithm("HS384"), hashlib.sha384)
        self.assertEqual(client.get_hash_algorithm("HS512"), hashlib.sha512)

        # Test unsupported algorithm
        self.assertIsNone(client.get_hash_algorithm("UNSUPPORTED"))

    @override_settings(OPENID_CONNECT_AUTH_SERVERS=OPENID_CONNECT_AUTH_SERVERS)
    @patch.object(jwt, "get_unverified_header")
    def test_validate_access_token_valid(self, mock_get_unverified_header):
        """Validates access token with correct at_hash"""
        client = OpenIDClient("default")

        # Create a valid at_hash for the access token
        access_token = "test_access_token"
        hash_digest = hashlib.sha256(access_token.encode("ascii")).digest()
        left_half = hash_digest[: len(hash_digest) // 2]
        expected_at_hash = (
            base64.urlsafe_b64encode(left_half).decode("ascii").rstrip("=")
        )

        verified_id_token = {"sub": "1234567890", "at_hash": expected_at_hash}
        id_token = "header.payload.signature"

        mock_get_unverified_header.return_value = {"alg": "RS256"}

        result = client.validate_access_token(verified_id_token, id_token, access_token)

        self.assertTrue(result)
        mock_get_unverified_header.assert_called_once_with(id_token)

    @override_settings(OPENID_CONNECT_AUTH_SERVERS=OPENID_CONNECT_AUTH_SERVERS)
    def test_validate_access_token_missing_at_hash(self):
        """Returns False when at_hash is missing from ID token"""
        client = OpenIDClient("default")

        verified_id_token = {
            "sub": "1234567890"
            # No at_hash
        }
        id_token = "header.payload.signature"
        access_token = "test_access_token"

        result = client.validate_access_token(verified_id_token, id_token, access_token)

        self.assertFalse(result)

    @override_settings(OPENID_CONNECT_AUTH_SERVERS=OPENID_CONNECT_AUTH_SERVERS)
    @patch.object(jwt, "get_unverified_header")
    def test_validate_access_token_invalid_hash(self, mock_get_unverified_header):
        """Returns False when at_hash doesn't match access token"""
        client = OpenIDClient("default")

        verified_id_token = {"sub": "1234567890", "at_hash": "invalid_hash"}
        id_token = "header.payload.signature"
        access_token = "test_access_token"

        mock_get_unverified_header.return_value = {"alg": "RS256"}

        result = client.validate_access_token(verified_id_token, id_token, access_token)

        self.assertFalse(result)

    @override_settings(OPENID_CONNECT_AUTH_SERVERS=OPENID_CONNECT_AUTH_SERVERS)
    @patch.object(jwt, "get_unverified_header")
    def test_validate_access_token_unsupported_algorithm(
        self, mock_get_unverified_header
    ):
        """Raises ValueError for unsupported algorithm"""
        client = OpenIDClient("default")

        verified_id_token = {"sub": "1234567890", "at_hash": "some_hash"}
        id_token = "header.payload.signature"
        access_token = "test_access_token"

        mock_get_unverified_header.return_value = {"alg": "UNSUPPORTED"}

        with self.assertRaises(ValueError) as context:
            client.validate_access_token(verified_id_token, id_token, access_token)

        self.assertIn("Unsupported algorithm", str(context.exception))

    @override_settings(OPENID_CONNECT_AUTH_SERVERS=OPENID_CONNECT_AUTH_SERVERS)
    def test_blank_email_claims_fetch_user_info(self):
        """User info is fetched unless the token carries a non-blank address."""
        client = OpenIDClient("default")
        for claims, expected in [
            ({"email": ""}, True),
            ({"email": "  "}, True),
            ({"email": None}, True),
            ({"emails": ["", " "]}, True),
            ({"emails": "user@example.com"}, True),
            ({"emails": ["", "user@example.com"]}, False),
            ({"email": "", "emails": ["user@example.com"]}, False),
            ({"email": "user@example.com"}, False),
        ]:
            with self.subTest(claims=claims):
                self.assertEqual(
                    client.should_retrieve_user_info({"sub": "1", **claims}), expected
                )

    @override_settings(OPENID_CONNECT_AUTH_SERVERS=OPENID_CONNECT_AUTH_SERVERS)
    def test_tokens_to_user_info_email_in_id_token(self):
        """Returns ID token claims when email is present"""
        client = OpenIDClient("default")

        decoded_id_token = {
            "sub": "1234567890",
            "email": "user@example.com",
            "name": "John Doe",
        }
        id_token = "header.payload.signature"
        access_token = "access_token_value"

        result = client.tokens_to_user_info(decoded_id_token, id_token, access_token)

        self.assertEqual(result, decoded_id_token)

    @override_settings(
        OPENID_CONNECT_AUTH_SERVERS={
            "default": {
                **OPENID_CONNECT_AUTH_SERVERS["default"],
                "USER_INFO_ENDPOINT": "https://example.com/oauth2/userinfo",
            }
        }
    )
    @patch.object(OpenIDClient, "retrieve_user_info")
    @patch.object(OpenIDClient, "validate_access_token")
    def test_tokens_to_user_info_no_email_valid_access_token(
        self, mock_validate_access_token, mock_retrieve_user_info
    ):
        """Fetches user info from endpoint when email missing and access token valid"""
        client = OpenIDClient("default")

        decoded_id_token = {
            "sub": "1234567890",
            "name": "John Doe",
            # No email
        }
        id_token = "header.payload.signature"
        access_token = "access_token_value"

        mock_validate_access_token.return_value = True
        mock_retrieve_user_info.return_value = {
            "sub": "1234567890",
            "email": "user@example.com",
            "name": "John Doe",
        }

        result = client.tokens_to_user_info(decoded_id_token, id_token, access_token)

        self.assertEqual(
            result,
            {"sub": "1234567890", "email": "user@example.com", "name": "John Doe"},
        )
        mock_validate_access_token.assert_called_once_with(
            decoded_id_token, id_token, access_token
        )
        mock_retrieve_user_info.assert_called_once_with(access_token)

    @override_settings(OPENID_CONNECT_AUTH_SERVERS=OPENID_CONNECT_AUTH_SERVERS)
    @patch.object(OpenIDClient, "validate_access_token")
    def test_tokens_to_user_info_no_email_invalid_access_token(
        self, mock_validate_access_token
    ):
        """Raises exception when email missing and access token invalid"""
        client = OpenIDClient("default")

        decoded_id_token = {
            "sub": "1234567890",
            "name": "John Doe",
            "at_hash": "some_hash",
            # No email
        }
        id_token = "header.payload.signature"
        access_token = "access_token_value"

        mock_validate_access_token.return_value = False

        with self.assertRaises(TokenVerificationFailed) as context:
            client.tokens_to_user_info(decoded_id_token, id_token, access_token)

        self.assertIn("at_hash does not match", str(context.exception))

    @override_settings(OPENID_CONNECT_AUTH_SERVERS=OPENID_CONNECT_AUTH_SERVERS)
    def test_tokens_to_user_info_no_email_no_access_token(self):
        """Raises exception when email missing and no access token provided"""
        client = OpenIDClient("default")

        decoded_id_token = {
            "sub": "1234567890",
            "name": "John Doe",
            # No email
        }
        id_token = "header.payload.signature"
        access_token = None

        with self.assertRaises(TokenVerificationFailed) as context:
            client.tokens_to_user_info(decoded_id_token, id_token, access_token)

        self.assertIn("no access token", str(context.exception))

    @override_settings(OPENID_CONNECT_AUTH_SERVERS=OPENID_CONNECT_AUTH_SERVERS)
    def test_tokens_to_user_info_id_token_without_at_hash(self):
        """An ID token with no ``at_hash`` fails verification with its own reason."""
        client = OpenIDClient("default")

        with self.assertRaises(TokenVerificationFailed) as context:
            client.tokens_to_user_info(
                {"sub": "1234567890"}, "header.payload.signature", "access_token"
            )

        self.assertIn("ID token has no at_hash", str(context.exception))

    @override_settings(OPENID_CONNECT_AUTH_SERVERS=OPENID_CONNECT_AUTH_SERVERS)
    def test_tokens_to_user_info_non_string_access_token(self):
        """A non-string access token fails verification with a fixed reason."""
        client = OpenIDClient("default")

        with self.assertRaises(TokenVerificationFailed) as context:
            client.tokens_to_user_info(
                {"sub": "1234567890", "at_hash": "some_hash"},
                "header.payload.signature",
                12345,
            )

        self.assertIn("cannot compute at_hash", str(context.exception))

    @override_settings(OPENID_CONNECT_AUTH_SERVERS=OPENID_CONNECT_AUTH_SERVERS)
    @patch.object(jwt, "get_unverified_header")
    def test_tokens_to_user_info_non_ascii_access_token(
        self, mock_get_unverified_header
    ):
        """A non-ASCII access token fails verification with a fixed reason. The
        ``UnicodeEncodeError``, which holds the token, is not chained."""
        client = OpenIDClient("default")
        decoded_id_token = {"sub": "1234567890", "at_hash": "some_hash"}
        mock_get_unverified_header.return_value = {"alg": "RS256"}

        with self.assertRaises(TokenVerificationFailed) as context:
            client.tokens_to_user_info(
                decoded_id_token, "header.payload.signature", "t\u00f6ken"
            )

        mock_get_unverified_header.assert_called_once_with("header.payload.signature")
        self.assertIn("cannot compute at_hash", str(context.exception))
        self.assertIsNone(context.exception.__context__)

    @override_settings(
        OPENID_CONNECT_AUTH_SERVERS={
            "default": {
                **OPENID_CONNECT_AUTH_SERVERS["default"],
                "VERIFY_ACCESS_TOKEN": False,
            }
        }
    )
    @patch.object(OpenIDClient, "retrieve_user_info")
    @patch.object(OpenIDClient, "validate_access_token")
    def test_tokens_to_user_info_skips_check_when_disabled(
        self, mock_validate_access_token, mock_retrieve_user_info
    ):
        """With ``VERIFY_ACCESS_TOKEN`` off, userinfo is fetched without an ``at_hash``
        check."""
        mock_retrieve_user_info.return_value = {"email": "jdoe@example.com"}
        client = OpenIDClient("default")
        self.assertFalse(client.should_verify_access_token)

        user_info = client.tokens_to_user_info(
            {"sub": "1234567890"}, "header.payload.signature", "access_token_value"
        )

        self.assertEqual(user_info, {"email": "jdoe@example.com"})
        mock_validate_access_token.assert_not_called()
        mock_retrieve_user_info.assert_called_once_with("access_token_value")

    @override_settings(
        OPENID_CONNECT_AUTH_SERVERS={
            "default": {
                "AUTHORIZATION_ENDPOINT": (
                    "https://example.com/oauth2/v2.0/authorize"
                ),
                "CLIENT_ID": "client",
                "JWKS_ENDPOINT": "https://example.com/discovery/v2.0/keys",
                "SCOPE": "openid profile",
                "TOKEN_ENDPOINT": "https://example.com/oauth2/v2.0/token",
                "END_SESSION_ENDPOINT": "http://localhost:3000",
                "REDIRECT_URI": "http://localhost:8000/oidc/msft/callback",
                "RESPONSE_TYPE": "code",
                "RESPONSE_MODE": "form_post",
                "USE_NONCES": False,
                "NONCE_CACHE_TIMEOUT": 600,
            }
        }
    )
    @patch("oidc.client.RSAAlgorithm.from_jwk")
    @patch("oidc.client.jwt.decode")
    @patch("oidc.client.jwt.get_unverified_header")
    @patch.object(OpenIDClient, "_retrieve_jwks_related_to_kid")
    @patch.object(secrets, "token_urlsafe")
    def test_next_round_trip_with_use_nonces_false(
        self,
        mock_token_urlsafe,
        mock_jwks,
        mock_get_header,
        mock_jwt_decode,
        _mock_from_jwk,
    ):
        """Regression test for #116: with ``USE_NONCES=False``, a
        ``next`` value passed to ``login()`` is restored on the
        callback so the post-auth redirect honors it.

        Before the fix, ``verify_and_decode_id_token`` only restored
        ``REDIRECT_AFTER_AUTH`` from cache inside the
        ``cache_nonces=True`` branch, so the value was silently
        dropped when nonces were disabled.
        """
        mock_token_urlsafe.return_value = "n1"
        mock_jwks.return_value = {"kty": "RSA"}
        mock_get_header.return_value = {"kid": "k1", "alg": "RS256"}
        mock_jwt_decode.return_value = {"sub": "1", "nonce": "n1"}

        client = OpenIDClient("default")
        client.login(redirect_after="/dashboard")

        self.assertIsNotNone(cache.get("n1"))

        decoded = client.verify_and_decode_id_token("h.p.s")

        self.assertEqual(decoded[REDIRECT_AFTER_AUTH], "/dashboard")
        self.assertIsNone(cache.get("n1"))

    @override_settings(
        OPENID_CONNECT_AUTH_SERVERS={
            "default": {
                "AUTHORIZATION_ENDPOINT": (
                    "https://example.com/oauth2/v2.0/authorize"
                ),
                "CLIENT_ID": "client",
                "JWKS_ENDPOINT": "https://example.com/discovery/v2.0/keys",
                "SCOPE": "openid profile",
                "TOKEN_ENDPOINT": "https://example.com/oauth2/v2.0/token",
                "END_SESSION_ENDPOINT": "http://localhost:3000",
                "REDIRECT_URI": "http://localhost:8000/oidc/msft/callback",
                "RESPONSE_TYPE": "code",
                "RESPONSE_MODE": "form_post",
                "USE_NONCES": False,
                "NONCE_CACHE_TIMEOUT": 600,
            }
        }
    )
    @patch("oidc.client.RSAAlgorithm.from_jwk")
    @patch("oidc.client.jwt.decode")
    @patch("oidc.client.jwt.get_unverified_header")
    @patch.object(OpenIDClient, "_retrieve_jwks_related_to_kid")
    def test_no_next_with_use_nonces_false_does_not_set_redirect_after(
        self,
        mock_jwks,
        mock_get_header,
        mock_jwt_decode,
        _mock_from_jwk,
    ):
        """``USE_NONCES=False`` and no ``next``: nothing is cached,
        ``verify_and_decode_id_token`` does not invent a redirect
        target. ``REDIRECT_AFTER_AUTH`` is absent from the decoded
        token so the viewset falls back to the configured default."""
        mock_jwks.return_value = {"kty": "RSA"}
        mock_get_header.return_value = {"kid": "k1", "alg": "RS256"}
        mock_jwt_decode.return_value = {"sub": "1"}

        client = OpenIDClient("default")
        decoded = client.verify_and_decode_id_token("h.p.s")

        self.assertNotIn(REDIRECT_AFTER_AUTH, decoded)

    @override_settings(OPENID_CONNECT_AUTH_SERVERS=OPENID_CONNECT_AUTH_SERVERS)
    @patch("oidc.client.RSAAlgorithm.from_jwk")
    @patch("oidc.client.jwt.decode")
    @patch("oidc.client.jwt.get_unverified_header")
    @patch.object(OpenIDClient, "_retrieve_jwks_related_to_kid")
    @patch.object(secrets, "token_urlsafe")
    def test_nonce_is_single_use(
        self,
        mock_token_urlsafe,
        mock_jwks,
        mock_get_header,
        mock_jwt_decode,
        _mock_from_jwk,
    ):
        """Replaying an ID token after its nonce was verified fails (#143)."""
        mock_token_urlsafe.return_value = "n1"
        mock_jwks.return_value = {"kty": "RSA"}
        mock_get_header.return_value = {"kid": "k1", "alg": "RS256"}
        mock_jwt_decode.return_value = {"sub": "1", "nonce": "n1"}

        client = OpenIDClient("default")
        self.assertTrue(client.cache_nonces)
        client.login()
        self.assertIsNotNone(cache.get("n1"))

        self.assertEqual(client.verify_and_decode_id_token("h.p.s")["sub"], "1")
        self.assertIsNone(cache.get("n1"))

        with self.assertRaises(NonceVerificationFailed):
            client.verify_and_decode_id_token("h.p.s")

    @override_settings(OPENID_CONNECT_AUTH_SERVERS=OPENID_CONNECT_AUTH_SERVERS)
    @patch("oidc.client.RSAAlgorithm.from_jwk")
    @patch("oidc.client.jwt.decode")
    @patch("oidc.client.jwt.get_unverified_header")
    @patch.object(OpenIDClient, "_retrieve_jwks_related_to_kid")
    @patch.object(secrets, "token_urlsafe")
    def test_nonce_consumed_by_concurrent_request_is_refused(
        self,
        mock_token_urlsafe,
        mock_jwks,
        mock_get_header,
        mock_jwt_decode,
        _mock_from_jwk,
    ):
        """Two requests can read the nonce before either deletes it; the
        one whose delete finds nothing left must fail."""
        mock_token_urlsafe.return_value = "n1"
        mock_jwks.return_value = {"kty": "RSA"}
        mock_get_header.return_value = {"kid": "k1", "alg": "RS256"}
        mock_jwt_decode.return_value = {"sub": "1", "nonce": "n1"}

        client = OpenIDClient("default")
        client.login()
        self.assertIsNotNone(cache.get("n1"))

        with patch.object(cache, "delete", return_value=False) as mock_delete:
            with self.assertRaises(NonceVerificationFailed):
                client.verify_and_decode_id_token("h.p.s")
        mock_delete.assert_called_once_with("n1")

    @override_settings(OPENID_CONNECT_AUTH_SERVERS=OPENID_CONNECT_AUTH_SERVERS)
    @patch("oidc.client.RSAAlgorithm.from_jwk")
    @patch("oidc.client.jwt.decode")
    @patch("oidc.client.jwt.get_unverified_header")
    @patch.object(OpenIDClient, "_retrieve_jwks_related_to_kid")
    def test_nonce_naming_unrelated_cache_entry_leaves_it_alone(
        self,
        mock_jwks,
        mock_get_header,
        mock_jwt_decode,
        _mock_from_jwk,
    ):
        """The IdP echoes whatever nonce the authorize URL carried, so a
        user can make it name any cache key. Only entries ``login()`` wrote
        for this provider may be consumed."""
        mock_jwks.return_value = {"kty": "RSA"}
        mock_get_header.return_value = {"kid": "k1", "alg": "RS256"}
        unrelated = {
            "throttle_login_1.2.3.4": [1, 2, 3],
            "lockout": {"attempts": 5},
            "pkce-nonce": {"auth_server": "pkce", "redirect_after": None},
        }
        cache.set_many(unrelated)
        client = OpenIDClient("default")

        for key, value in unrelated.items():
            mock_jwt_decode.return_value = {"sub": "1", "nonce": key}
            with self.assertRaises(NonceVerificationFailed):
                client.verify_and_decode_id_token("h.p.s")
            self.assertEqual(cache.get(key), value)


ID_TOKEN_VALIDATION_AUTH_SERVERS = {
    "default": {
        **OPENID_CONNECT_AUTH_SERVERS["default"],
        "USE_NONCES": False,
    }
}


@override_settings(OPENID_CONNECT_AUTH_SERVERS=ID_TOKEN_VALIDATION_AUTH_SERVERS)
class IDTokenValidationTestCase(TestCase):
    """Signature-level tests for ID token verification.

    These sign real tokens with a real RSA keypair and run real
    verification; only the JWKS network fetch is mocked.
    """

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.private_key = rsa.generate_private_key(
            public_exponent=65537, key_size=2048
        )
        jwk = json.loads(RSAAlgorithm.to_jwk(cls.private_key.public_key()))
        jwk["kid"] = "test-kid"
        cls.jwks = {"keys": [jwk]}

    def _claims(self, **overrides):
        now = int(time.time())
        claims = {"aud": "client", "iat": now, "exp": now + 300, "sub": "user-1"}
        claims.update(overrides)
        return {k: v for k, v in claims.items() if v is not None}

    def _sign(self, claims):
        return jwt.encode(
            claims, self.private_key, algorithm="RS256", headers={"kid": "test-kid"}
        )

    def _verify(self, token):
        jwks_response = MagicMock(
            status_code=200, **{"json.return_value": self.jwks}
        )
        with patch.object(requests, "get", return_value=jwks_response):
            return OpenIDClient("default").verify_and_decode_id_token(token)

    def test_valid_rs256_token_decodes(self):
        """A properly signed RS256 token with the expected audience decodes."""
        decoded = self._verify(self._sign(self._claims()))
        self.assertEqual(decoded["sub"], "user-1")

    def test_header_chosen_algorithm_outside_allowlist_is_rejected(self):
        """The token's own alg header cannot select the verification algorithm."""
        cases = {
            "HS256 with a guessed shared secret": jwt.encode(
                self._claims(), "guess", algorithm="HS256", headers={"kid": "test-kid"}
            ),
            "unsigned alg=none": jwt.encode(
                self._claims(), None, algorithm="none", headers={"kid": "test-kid"}
            ),
        }
        for name, token in cases.items():
            with self.subTest(name):
                with self.assertRaises(jwt.InvalidTokenError):
                    self._verify(token)

    @override_settings(
        OPENID_CONNECT_AUTH_SERVERS={
            "default": {
                **ID_TOKEN_VALIDATION_AUTH_SERVERS["default"],
                "ID_TOKEN_ALLOWED_ALGORITHMS": ["RS256"],
            }
        }
    )
    def test_configured_algorithm_allowlist_narrows_the_default(self):
        """A configured allowlist rejects an RSA-family algorithm it omits."""
        rs384_token = jwt.encode(
            self._claims(),
            self.private_key,
            algorithm="RS384",
            headers={"kid": "test-kid"},
        )
        with self.assertRaises(jwt.InvalidTokenError):
            self._verify(rs384_token)
        decoded = self._verify(self._sign(self._claims()))
        self.assertEqual(decoded["sub"], "user-1")

    def test_default_allowlist_covers_the_rsa_family(self):
        """With no allowlist configured, other RSA-family algorithms verify."""
        rs384_token = jwt.encode(
            self._claims(),
            self.private_key,
            algorithm="RS384",
            headers={"kid": "test-kid"},
        )
        decoded = self._verify(rs384_token)
        self.assertEqual(decoded["sub"], "user-1")

    def test_invalid_algorithm_allowlist_config_is_rejected(self):
        """An allowlist outside the RSA family fails at client construction."""
        for name, value in {
            "symmetric algorithm": ["RS256", "HS256"],
            "non-RSA asymmetric algorithm": ["ES256"],
            "empty list": [],
            "bare string instead of a list": "RS256",
        }.items():
            with self.subTest(name):
                with override_settings(
                    OPENID_CONNECT_AUTH_SERVERS={
                        "default": {
                            **ID_TOKEN_VALIDATION_AUTH_SERVERS["default"],
                            "ID_TOKEN_ALLOWED_ALGORITHMS": value,
                        }
                    }
                ):
                    with self.assertRaises(ImproperlyConfigured):
                        OpenIDClient("default")

    @override_settings(
        OPENID_CONNECT_AUTH_SERVERS={
            "default": {
                **ID_TOKEN_VALIDATION_AUTH_SERVERS["default"],
                "ISSUER": "https://idp.example.com",
            }
        }
    )
    def test_configured_issuer_is_enforced(self):
        """With ISSUER set, a token with the wrong or no iss is rejected."""
        for name, iss in {
            "wrong issuer": "https://evil.example.com",
            "missing issuer": None,
        }.items():
            with self.subTest(name):
                with self.assertRaises(jwt.InvalidTokenError):
                    self._verify(self._sign(self._claims(iss=iss)))
        decoded = self._verify(
            self._sign(self._claims(iss="https://idp.example.com"))
        )
        self.assertEqual(decoded["sub"], "user-1")

    @override_settings(
        OPENID_CONNECT_AUTH_SERVERS={
            "default": {
                **ID_TOKEN_VALIDATION_AUTH_SERVERS["default"],
                "ISSUER": "https://idp.example.com/tenant",
            }
        }
    )
    def test_issuer_substring_match_is_rejected(self):
        """A token iss that is only a substring of ISSUER is rejected.

        PyJWT 2.10.0 matched issuers by substring containment
        (GHSA-75c5-xw7c-p5pm) and accepted both of these tokens;
        setup.cfg requires >=2.10.1 so the match stays exact.
        """
        for name, iss in {
            "prefix of the configured issuer": "https://idp.example.com/",
            "empty issuer": "",
        }.items():
            with self.subTest(name):
                with self.assertRaises(jwt.InvalidTokenError):
                    self._verify(self._sign(self._claims(iss=iss)))

    def test_missing_issuer_config_logs_warning(self):
        """Verification without a configured ISSUER warns that iss is unchecked."""
        with self.assertLogs("oidc.client", level="WARNING") as logs:
            self._verify(self._sign(self._claims()))
        self.assertIn("ISSUER", "\n".join(logs.output))

    def test_token_missing_required_claims_is_rejected(self):
        """A token lacking exp, iat or sub is rejected despite a valid signature."""
        for missing in ("exp", "iat", "sub"):
            with self.subTest(missing=missing):
                with self.assertRaises(jwt.InvalidTokenError):
                    self._verify(self._sign(self._claims(**{missing: None})))

    def test_kid_resolving_to_non_rsa_key_is_a_handled_rejection(self):
        """A kid that resolves to a non-RSA JWKS key rejects, not crashes."""
        ec_key = ec.generate_private_key(ec.SECP256R1())
        jwk = json.loads(ECAlgorithm.to_jwk(ec_key.public_key()))
        jwk["kid"] = "ec-kid"
        token = jwt.encode(
            self._claims(), ec_key, algorithm="ES256", headers={"kid": "ec-kid"}
        )
        jwks_response = MagicMock(
            status_code=200, **{"json.return_value": {"keys": [jwk]}}
        )
        with patch.object(requests, "get", return_value=jwks_response):
            with self.assertRaises(NoJSONWebKeyFound):
                OpenIDClient("default").verify_and_decode_id_token(token)

    @override_settings(
        OPENID_CONNECT_AUTH_SERVERS={
            "default": {**ID_TOKEN_VALIDATION_AUTH_SERVERS["default"], "ISSUER": ""}
        }
    )
    def test_empty_issuer_behaves_like_unset(self):
        """ISSUER='' skips the iss check with the warning, same as unset."""
        with self.assertLogs("oidc.client", level="WARNING"):
            decoded = self._verify(self._sign(self._claims()))
        self.assertEqual(decoded["sub"], "user-1")

    def test_small_clock_skew_is_tolerated(self):
        """A token whose iat is seconds ahead (IdP clock skew) verifies."""
        decoded = self._verify(self._sign(self._claims(iat=int(time.time()) + 10)))
        self.assertEqual(decoded["sub"], "user-1")

    def test_expired_token_is_rejected(self):
        """A token past its exp, beyond any leeway, is rejected."""
        past = int(time.time()) - 3600
        with self.assertRaises(jwt.InvalidTokenError):
            self._verify(self._sign(self._claims(iat=past, exp=past + 300)))

    def test_token_signed_with_a_different_key_is_rejected(self):
        """A signature from any key other than the JWKS key fails."""
        other = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        token = jwt.encode(
            self._claims(), other, algorithm="RS256", headers={"kid": "test-kid"}
        )
        with self.assertRaises(jwt.InvalidTokenError):
            self._verify(token)

    def test_wrong_audience_is_rejected(self):
        """A token minted for a different client id is rejected."""
        with self.assertRaises(jwt.InvalidTokenError):
            self._verify(self._sign(self._claims(aud="other-client")))

    def test_multi_audience_token_needs_azp_naming_this_client(self):
        """A token with several audiences needs ``azp`` equal to the client id."""
        for name, azp, error in [
            ("missing azp", None, jwt.MissingRequiredClaimError),
            ("azp naming another client", "other-client", jwt.InvalidAudienceError),
        ]:
            with self.subTest(name):
                with self.assertRaises(error):
                    self._verify(
                        self._sign(self._claims(aud=["client", "other"], azp=azp))
                    )
        decoded = self._verify(
            self._sign(self._claims(aud=["client", "other"], azp="client"))
        )
        self.assertEqual(decoded["sub"], "user-1")

    def test_single_audience_token_does_not_need_azp(self):
        """A token for this client alone verifies with or without ``azp``.

        This test passes without the ``azp`` check too. It fails if the
        check reaches these tokens.
        """
        for name, claims in {
            "audience list of one, no azp": {"aud": ["client"]},
            "this client listed twice, no azp": {"aud": ["client", "client"]},
            "audience string, azp of another client": {
                "aud": "client",
                "azp": "mobile-client",
            },
        }.items():
            with self.subTest(name):
                decoded = self._verify(self._sign(self._claims(**claims)))
                self.assertEqual(decoded["sub"], "user-1")

    def _verify_with_settings(self, token, **overrides):
        servers = {
            "default": {**ID_TOKEN_VALIDATION_AUTH_SERVERS["default"], **overrides}
        }
        with override_settings(OPENID_CONNECT_AUTH_SERVERS=servers):
            return self._verify(token)

    def test_azp_check_can_be_turned_off(self):
        """With ``ID_TOKEN_VERIFY_AZP`` off, a multi-audience token needs no ``azp``."""
        tokens = {
            "missing azp": self._sign(self._claims(aud=["client", "other"])),
            "azp naming another client": self._sign(
                self._claims(aud=["client", "other"], azp="other-client")
            ),
        }
        for name, token in tokens.items():
            with self.subTest(name):
                with self.assertRaises(jwt.InvalidTokenError):
                    self._verify(token)
                for value in (False, "False"):
                    decoded = self._verify_with_settings(
                        token, ID_TOKEN_VERIFY_AZP=value
                    )
                    self.assertEqual(decoded["sub"], "user-1")

    def test_sub_requirement_can_be_turned_off(self):
        """With ``ID_TOKEN_REQUIRE_SUB`` off, a token without ``sub`` decodes."""
        token = self._sign(self._claims(sub=None))
        with self.assertRaises(jwt.MissingRequiredClaimError):
            self._verify(token)
        for value in (False, "False"):
            with self.subTest(value=value):
                decoded = self._verify_with_settings(token, ID_TOKEN_REQUIRE_SUB=value)
                self.assertNotIn("sub", decoded)
                self.assertEqual(decoded["aud"], "client")


class SealLoginBindingTestCase(TestCase):
    """Contract of the binding slot names and the sealed value."""

    def test_sealed_value_matches_only_its_own_state(self):
        """A sealed binding matches the state it was minted for, no other."""
        cookies = {login_binding_cookie_names()[0]: seal_login_binding("state-1")}
        self.assertTrue(login_binding_matches(cookies, "state-1"))
        self.assertFalse(login_binding_matches(cookies, "state-2"))

    def test_the_slot_names_are_a_fixed_set(self):
        """Exactly LOGIN_BINDING_SLOTS distinct slot names exist."""
        names = login_binding_cookie_names()
        self.assertEqual(len(names), LOGIN_BINDING_SLOTS)
        self.assertEqual(len(set(names)), LOGIN_BINDING_SLOTS)

    def test_slot_names_carry_the_public_prefix(self):
        """Every slot cookie name starts with the shared prefix."""
        for name in login_binding_cookie_names():
            self.assertTrue(name.startswith(LOGIN_BINDING_COOKIE_PREFIX))

    def test_a_binding_matches_from_any_slot(self):
        """The slot holding a binding carries no meaning for the match."""
        for name in login_binding_cookie_names():
            with self.subTest(slot=name):
                cookies = {name: seal_login_binding("state-1")}
                self.assertTrue(login_binding_matches(cookies, "state-1"))


class AllocateLoginBindingSlotTestCase(TestCase):
    """Contract of the login-start slot allocation."""

    @staticmethod
    def _sealed_at(state, issued_at):
        with patch("time.time", return_value=issued_at):
            return seal_login_binding(state)

    def test_allocation_only_returns_slot_names(self):
        """Every allocation lands on one of the fixed slot names."""
        names = set(login_binding_cookie_names())
        for _ in range(LOGIN_BINDING_SLOTS * 3):
            self.assertIn(allocate_login_binding_slot({}), names)

    def test_starts_racing_on_one_jar_take_different_slots(self):
        """Two starts that share a cookie jar do not overwrite each other.

        Requests racing before any response lands all present the same
        jar; the allocations they trigger must still spread out, or one
        login's binding would overwrite the other's.
        """
        self.assertNotEqual(
            allocate_login_binding_slot({}), allocate_login_binding_slot({})
        )

    def test_a_pending_attempt_keeps_its_slot_while_one_is_free(self):
        """No pending binding is overwritten while any slot is free."""
        jar = {}
        for i in range(LOGIN_BINDING_SLOTS - 1):
            jar[allocate_login_binding_slot(jar)] = seal_login_binding(f"state-{i}")
        self.assertNotIn(allocate_login_binding_slot(jar), jar)

    def test_a_full_jar_reuses_the_oldest_attempts_slot(self):
        """With every slot pending, the oldest attempt's slot is evicted."""
        start = time.time() - 100
        jar = {}
        oldest_name = None
        for i, name in enumerate(login_binding_cookie_names()):
            # Issue times are one second apart so age ordering is
            # unambiguous; slot 2 is deliberately the oldest, so name
            # order cannot accidentally satisfy the assertion.
            age_rank = (i - 2) % LOGIN_BINDING_SLOTS
            jar[name] = self._sealed_at(f"state-{i}", start + age_rank)
            if age_rank == 0:
                oldest_name = name
        self.assertEqual(allocate_login_binding_slot(jar), oldest_name)

    def test_a_broken_slot_is_taken_before_any_attempt_is_evicted(self):
        """A slot holding a tampered value is free, sparing pending ones."""
        jar = {
            name: seal_login_binding(f"state-{i}")
            for i, name in enumerate(login_binding_cookie_names())
        }
        broken = login_binding_cookie_names()[3]
        jar[broken] = jar[broken][:-1]
        self.assertEqual(allocate_login_binding_slot(jar), broken)


class StaleLoginBindingCookiesTestCase(TestCase):
    """Contract of the login-start cleanup helper."""

    def test_valid_slot_cookies_are_kept(self):
        """A pending attempt's binding is never named for deletion."""
        jar = {
            name: seal_login_binding(f"state-{i}")
            for i, name in enumerate(login_binding_cookie_names())
        }
        self.assertEqual(stale_login_binding_cookies(jar), [])

    def test_broken_slot_cookies_are_named_for_deletion(self):
        """A tampered slot value is named for deletion."""
        name = login_binding_cookie_names()[0]
        jar = {name: seal_login_binding("state-1")[:-1]}
        self.assertEqual(stale_login_binding_cookies(jar), [name])

    def test_prefixed_cookies_outside_the_slot_set_are_named_for_deletion(self):
        """A binding-prefixed cookie outside the slot set is named for deletion.

        Nothing can read such a cookie, so leaving it would grow the
        Cookie header until the cookie expires.
        """
        name = f"{LOGIN_BINDING_COOKIE_PREFIX}deadbeef"
        self.assertEqual(stale_login_binding_cookies({name: "junk"}), [name])

    def test_cookies_without_the_binding_prefix_are_ignored(self):
        """Unrelated cookies are never named for deletion."""
        self.assertEqual(
            stale_login_binding_cookies({"sessionid": "abc", "csrftoken": "def"}),
            [],
        )


class LoginBindingMatchesTestCase(TestCase):
    """Contract of the callback-side login binding check."""

    def setUp(self):
        self.cookie_name = login_binding_cookie_names()[2]
        self.cookies = {self.cookie_name: seal_login_binding("state-1")}

    def test_missing_cookie_binds_nothing(self):
        """Without this attempt's binding no state is bound."""
        self.assertFalse(login_binding_matches({}, "state-1"))
        self.assertFalse(login_binding_matches({"other": "value"}, "state-1"))

    def test_missing_state_never_matches(self):
        """A response without a state cannot be bound, cookies or not."""
        self.assertFalse(login_binding_matches(self.cookies, None))
        self.assertFalse(login_binding_matches(self.cookies, ""))

    def test_non_string_state_never_matches(self):
        """A non-string state is unbindable instead of raising.

        A JSON callback body can carry any value under ``state``; a
        truthy non-string one must be rejected like a wrong state.
        """
        self.assertFalse(login_binding_matches(self.cookies, 1))
        self.assertFalse(login_binding_matches(self.cookies, ["state-1"]))

    def test_sealed_value_for_another_state_never_matches(self):
        """A slot holding another attempt's binding cannot match.

        The signed value holds the full state digest, so no slot
        shuffling can satisfy the check for a different state.
        """
        cookies = {self.cookie_name: seal_login_binding("state-2")}
        self.assertFalse(login_binding_matches(cookies, "state-1"))

    def test_the_match_names_the_slot_holding_the_binding(self):
        """The matching helper returns the slot the binding lives in."""
        self.assertEqual(
            matching_login_binding_cookie(self.cookies, "state-1"),
            self.cookie_name,
        )
        self.assertIsNone(matching_login_binding_cookie(self.cookies, "state-2"))

    def test_tampered_cookie_matches_nothing(self):
        """A value failing signature verification binds no state."""
        tampered = {self.cookie_name: self.cookies[self.cookie_name][:-1]}
        self.assertFalse(login_binding_matches(tampered, "state-1"))

    def test_cookie_expires_after_the_max_age(self):
        """The binding holds just before the max age and expires after it."""
        now = time.time()
        with patch("time.time", return_value=now + LOGIN_BINDING_MAX_AGE - 60):
            self.assertTrue(login_binding_matches(self.cookies, "state-1"))
        with patch("time.time", return_value=now + LOGIN_BINDING_MAX_AGE + 1):
            self.assertFalse(login_binding_matches(self.cookies, "state-1"))

    def test_value_signed_without_the_binding_salt_matches_nothing(self):
        """A signature minted for any other purpose cannot bind a login.

        Even a payload carrying the right digest fails when signed
        without the binding salt.
        """
        digest = hashlib.sha256(b"state-1").hexdigest()
        self.assertFalse(
            login_binding_matches({self.cookie_name: signing.dumps(digest)}, "state-1")
        )
