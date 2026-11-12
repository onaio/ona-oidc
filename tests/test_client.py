"""Tests for module oidc.client"""

import base64
import hashlib
import json
import secrets
import traceback
from unittest.mock import MagicMock, patch
from urllib.parse import quote

from django.core.cache import cache
from django.core.exceptions import ImproperlyConfigured
from django.http import HttpResponseRedirect
from django.test import TestCase
from django.test.utils import override_settings

import jwt
import requests

from oidc.client import (
    REDACTED,
    REDIRECT_AFTER_AUTH,
    REQUEST_MODES,
    TOKEN_RESPONSE_LOG_LIMIT,
    OpenIDClient,
    TokenVerificationFailed,
    state_cache_key,
)

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

        unchanged_tail = "response_mode=form_post&nonce=123"

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

    def _token_response(self, status_code, content):
        response = requests.Response()
        response.status_code = status_code
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
    def test_retrieve_tokens_failure_redacts_echoed_request(self, mock_requests_post):
        """
        A provider that echoes the request into its error fields leaks nothing.
        The message has only the status, and the report redacts the body.
        """
        code, verifier = "c0de-value", "v3rifier/value"
        echoed = f"{LEAKY_SECRET} {code} {quote(verifier, safe='')}"
        body = {"error": "invalid_grant", "error_description": echoed}
        for mode in REQUEST_MODES:
            server = {**QUERY_MODE_AUTH_SERVERS["pkce"], "REQUEST_MODE": mode}
            mock_requests_post.return_value = self._token_response(
                400, json.dumps(body).encode()
            )
            with (
                self.subTest(mode),
                override_settings(OPENID_CONNECT_AUTH_SERVERS={"pkce": server}),
                self.assertLogs("oidc.client", level="DEBUG") as logs,
                self.assertRaises(TokenVerificationFailed),
            ):
                OpenIDClient("pkce").retrieve_tokens_using_auth_code(code, verifier)

            details = logs.records[0].token_response
            self.assertIn("HTTP 400", "\n".join(logs.output))
            self.assertIn("invalid_grant", details["body"])
            self.assertEqual(details["body"].count(REDACTED), 3)
            reported = "\n".join(logs.output) + details["body"]
            for value in (LEAKY_SECRET, code, quote(verifier, safe="")):
                self.assertNotIn(value, reported)

    @override_settings(OPENID_CONNECT_AUTH_SERVERS=QUERY_MODE_AUTH_SERVERS)
    @patch.object(requests, "post")
    def test_retrieve_tokens_failure_report_is_truncated(self, mock_requests_post):
        """The report keeps only the start of a long response body"""
        mock_requests_post.return_value = self._token_response(502, b"x" * 5000)

        _logged, logs, _raised = self._retrieve_tokens_expecting_failure()

        details = logs.records[0].token_response
        self.assertEqual(details["body_length"], 5000)
        self.assertEqual(details["body"], "x" * TOKEN_RESPONSE_LOG_LIMIT)

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
            # No email
        }
        id_token = "header.payload.signature"
        access_token = "access_token_value"

        mock_validate_access_token.return_value = False

        with self.assertRaises(TokenVerificationFailed) as context:
            client.tokens_to_user_info(decoded_id_token, id_token, access_token)

        self.assertIn("Failed to validate access token", str(context.exception))

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

        self.assertIn("Failed to validate access token", str(context.exception))

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

        decoded = client.verify_and_decode_id_token("h.p.s")

        self.assertEqual(decoded[REDIRECT_AFTER_AUTH], "/dashboard")

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
