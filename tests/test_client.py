"""Tests for module oidc.client"""

import base64
import hashlib
import secrets
from unittest.mock import MagicMock, patch

from django.core.cache import cache
from django.http import HttpResponseRedirect
from django.test import TestCase
from django.test.utils import override_settings

import jwt
import requests

from oidc.client import OpenIDClient, TokenVerificationFailed

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
