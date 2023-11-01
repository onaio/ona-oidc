"""Tests for module oidc.client"""
import secrets

from unittest.mock import patch

from django.core.cache import cache
from django.http import HttpResponseRedirect
from django.test import TestCase
from django.test.utils import override_settings

from oidc.client import OpenIDClient

OPENID_CONNECT_AUTH_SERVERS = {
    "default": {
        "AUTHORIZATION_ENDPOINT": "example.com/oauth2/v2.0/authorize",
        "CLIENT_ID": "client",
        "JWKS_ENDPOINT": "example.com/discovery/v2.0/keys",
        "SCOPE": "openid profile",
        "TOKEN_ENDPOINT": "example.com/oauth2/v2.0/token",
        "END_SESSION_ENDPOINT": "http://localhost:3000",
        "REDIRECT_URI": "http://localhost:8000/oidc/msft/callback",
        "RESPONSE_TYPE": "code",
        "RESPONSE_MODE": "form_post",
        "USE_NONCES": False,
        "NONCE_CACHE_TIMEOUT": 600,
    }
}


class OpenIDClientTestCase(TestCase):
    """Tests for class OpenIDClient"""

    def setUp(self) -> None:
        super().setUp()

        self.maxDiff = None

    @override_settings(OPENID_CONNECT_AUTH_SERVERS=OPENID_CONNECT_AUTH_SERVERS)
    @patch.object(cache, "set")
    @patch.object(secrets, "randbits")
    def test_login(self, mock_randbits, mock_cache_set):
        """Returns redirect URL"""
        mock_randbits.return_value = "123"
        expected_url = (
            "example.com/oauth2/v2.0/authorize?"
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
                **OPENID_CONNECT_AUTH_SERVERS["default"],
                "NONCE_CACHE_TIMEOUT": None,
            }
        }
    )
    @patch.object(cache, "set")
    @patch.object(secrets, "randbits")
    def test_login_nonce_timeout_missing(self, mock_randbits, mock_cache_set):
        """Uses default nonce timeout on login if timeout not set"""
        mock_randbits.return_value = "123"
        expected_url = (
            "example.com/oauth2/v2.0/authorize?"
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
