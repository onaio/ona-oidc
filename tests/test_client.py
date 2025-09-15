"""Tests for module oidc.client"""

import base64
import hashlib
import secrets
from unittest.mock import MagicMock, patch

from django.core.cache import cache
from django.http import HttpResponseRedirect
from django.test import TestCase
from django.test.utils import override_settings

import requests

from oidc.client import OpenIDClient

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
        "REQUEST_TYPE": "form_post",
        "USE_PKCE": True,
        "PKCE_CODE_CHALLENGE_METHOD": "S256",
        "PKCE_CODE_CHALLENGE_TIMEOUT": 600,
        "PKCE_CODE_VERIFIER_LENGTH": 128,
    },
}


class OpenIDClientTestCase(TestCase):
    """Tests for class OpenIDClient"""

    def setUp(self) -> None:
        super().setUp()

        self.maxDiff = None
        cache.clear()

    @override_settings(OPENID_CONNECT_AUTH_SERVERS=OPENID_CONNECT_AUTH_SERVERS)
    @patch.object(cache, "set")
    @patch.object(secrets, "randbits")
    def test_login(self, mock_randbits, mock_cache_set):
        """Returns redirect URL"""
        mock_randbits.return_value = "123"
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
    @patch.object(secrets, "randbits")
    def test_login_nonce_timeout_missing(self, mock_randbits, mock_cache_set):
        """Uses default nonce timeout on login if timeout not set"""
        mock_randbits.return_value = "123"
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
        code_verifier = "123"
        mock_token_urlsafe.return_value = code_verifier
        code_verifier_hash = hashlib.sha256(code_verifier.encode("ascii")).digest()
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
            f"state=pkce_{expected_challenge}"
        )
        client = OpenIDClient("pkce")
        result = client.login()
        self.assertIsInstance(result, HttpResponseRedirect)
        self.assertEqual(result.url, expected_url)
        mock_cache_set.assert_called_once_with(
            f"pkce_{expected_challenge}",
            code_verifier,
            600,
        )
        mock_token_urlsafe.assert_called_once_with(128)

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
        code_verifier = "123"
        mock_token_urlsafe.return_value = code_verifier
        code_verifier_hash = hashlib.sha256(code_verifier.encode("ascii")).digest()
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
            f"state=pkce_{expected_challenge}"
        )
        client = OpenIDClient("pkce")
        result = client.login()
        self.assertIsInstance(result, HttpResponseRedirect)
        self.assertEqual(result.url, expected_url)
        # Default code verifier length is 64
        mock_token_urlsafe.assert_called_once_with(64)

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
        code_verifier = "123"
        mock_token_urlsafe.return_value = code_verifier
        code_verifier_hash = hashlib.sha256(code_verifier.encode("ascii")).digest()
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
            f"state=pkce_{expected_challenge}"
        )
        client = OpenIDClient("pkce")
        result = client.login()
        self.assertIsInstance(result, HttpResponseRedirect)
        self.assertEqual(result.url, expected_url)
        mock_cache_set.assert_called_once_with(
            f"pkce_{expected_challenge}",
            code_verifier,
            600,  # Default code challenge timeout is 600
        )

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
        code_verifier = "123"
        mock_token_urlsafe.return_value = code_verifier
        code_verifier_hash = hashlib.sha256(code_verifier.encode("ascii")).digest()
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
            f"state=pkce_{expected_challenge}"
        )
        client = OpenIDClient("pkce")
        result = client.login()
        self.assertIsInstance(result, HttpResponseRedirect)
        self.assertEqual(result.url, expected_url)

    @override_settings(OPENID_CONNECT_AUTH_SERVERS=OPENID_CONNECT_AUTH_SERVERS)
    @patch.object(requests, "post")
    def test_retrieve_token_using_auth_code_pkce_flow(self, mock_requests_post):
        """Retrieves an ID Token using the Authorization Code + PKCE flow"""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"id_token": "id_token"}
        mock_requests_post.return_value = mock_response

        client = OpenIDClient("pkce")
        result = client.retrieve_token_using_auth_code("auth_code", "123")

        self.assertEqual(result, "id_token")
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
                "REQUEST_TYPE": "query",
            }
        }
    )
    @patch.object(requests, "post")
    def test_retrieve_token_using_auth_code_pkce_flow_w_params(
        self, mock_requests_post
    ):
        """Retrieves an ID Token using the Authorization Code + PKCE flow with params"""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"id_token": "id_token"}
        mock_requests_post.return_value = mock_response

        client = OpenIDClient("pkce")
        result = client.retrieve_token_using_auth_code("auth_code", "123")

        self.assertEqual(result, "id_token")
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
