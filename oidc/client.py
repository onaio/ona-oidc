"""
Client module for the oidc app
"""

import base64
import hashlib
import json
import logging
import secrets
from typing import Optional

from django.conf import settings
from django.core.cache import cache
from django.http import HttpResponseRedirect

import jwt
import requests
from jwt.algorithms import RSAAlgorithm

import oidc.settings as default
from oidc.utils import str_to_bool

REDIRECT_AFTER_AUTH = "redirect_after_auth"

logger = logging.getLogger(__name__)


class NonceVerificationFailed(Exception):
    pass


class NoJSONWebKeyFound(Exception):
    pass


class TokenVerificationFailed(Exception):
    pass


class OpenIDClient:
    """
    OpenID connect client class
    """

    def __init__(self, auth_server: str) -> None:
        """
        Initializes an OpenID Connect Client object
        """
        config = getattr(settings, "OPENID_CONNECT_AUTH_SERVERS", {})
        default_config = getattr(default, "OPENID_CONNECT_AUTH_SERVERS", {})["default"]
        self.auth_server = auth_server
        self.authorization_endpoint = config[auth_server].get("AUTHORIZATION_ENDPOINT")
        self.client_id = config[auth_server].get("CLIENT_ID")
        self.client_secret = config[auth_server].get("CLIENT_SECRET")
        self.jwks_endpoint = config[auth_server].get("JWKS_ENDPOINT")
        self.scope = config[auth_server].get("SCOPE") or default_config["SCOPE"]
        self.token_endpoint = config[auth_server].get("TOKEN_ENDPOINT")
        self.end_session_endpoint = config[auth_server].get("END_SESSION_ENDPOINT")
        self.redirect_uri = config[auth_server].get("REDIRECT_URI")
        self.response_type = config[auth_server].get(
            "RESPONSE_TYPE", default_config["RESPONSE_TYPE"]
        )
        self.response_mode = config[auth_server].get(
            "RESPONSE_MODE", default_config["RESPONSE_MODE"]
        )
        self.cache_nonces = str_to_bool(
            config[auth_server].get("USE_NONCES", default_config["USE_NONCES"])
        )
        self.nonce_cache_timeout = int(
            config[auth_server].get(
                "NONCE_CACHE_TIMEOUT", default_config["NONCE_CACHE_TIMEOUT"]
            )
        )
        self.use_pkce = str_to_bool(
            config[auth_server].get("USE_PKCE", default_config["USE_PKCE"])
        )
        self.pkce_code_challenge_timeout = int(
            config[auth_server].get(
                "PKCE_CODE_CHALLENGE_TIMEOUT",
                default_config["PKCE_CODE_CHALLENGE_TIMEOUT"],
            )
        )
        self.pkce_code_challenge_method = config[auth_server].get(
            "PKCE_CODE_CHALLENGE_METHOD", default_config["PKCE_CODE_CHALLENGE_METHOD"]
        )
        self.pkce_code_verifier_length = int(
            config[auth_server].get(
                "PKCE_CODE_VERIFIER_LENGTH", default_config["PKCE_CODE_VERIFIER_LENGTH"]
            )
        )
        self.request_type = config[auth_server].get(
            "REQUEST_TYPE", default_config["REQUEST_TYPE"]
        )

    def _retrieve_jwks_related_to_kid(self, kid: str) -> Optional[str]:
        """
        Retrieves a JSON Web Key Set that can be used to verify a
        JSON web token issued by an authentication server.
        """
        response = requests.get(self.jwks_endpoint)
        if response.status_code == 200:
            jwks = response.json()
            for jwk in jwks.get("keys"):
                if jwk.get("kid") == kid:
                    return jwk
        return None

    def verify_and_decode_id_token(self, id_token: str) -> Optional[dict]:
        """
        Verifies that the received ID Token was signed and sent by the
        Authorization Server and that the client is one of the audiences
        of the key. If ID Token is valid returns a dict containing the tokens
        decoded information.
        """
        unverified_header = jwt.get_unverified_header(id_token)

        # Get public key thumbprint
        kid = unverified_header.get("kid")
        jwks = self._retrieve_jwks_related_to_kid(kid)

        if not jwks:
            raise NoJSONWebKeyFound("Failed to retrieve key ID described in Token")

        alg = unverified_header.get("alg")
        public_key = RSAAlgorithm.from_jwk(json.dumps(jwks))
        cached_data = {}

        decoded_token = jwt.decode(
            id_token, public_key, audience=[self.client_id], algorithms=alg
        )
        if self.cache_nonces:
            # Verify that the cached nonce is present and that
            # the provider the nonce was initiated for, is the same
            # provider returning it
            nonce = decoded_token.get("nonce")
            if not nonce:
                raise NonceVerificationFailed(
                    "Failed to verify login request. Missing nonce value"
                )
            cached_data = cache.get(nonce)
            if not cached_data or self.auth_server != cached_data.get("auth_server"):
                raise NonceVerificationFailed("Failed to verify returned nonce value")
            decoded_token[REDIRECT_AFTER_AUTH] = cached_data.get("redirect_after")
        return decoded_token

    def retrieve_token_using_auth_code(
        self, code: str, code_verifier: Optional[str] = None
    ) -> Optional[str]:
        """
        Obtain an ID Token using the Authorization Code flow

        :param code: Authorization code returned by the auth server
        :param code_verifier: Code verifier used in PKCE flow
        :return: ID Token as a string
        :raises TokenVerificationFailed: If the token retrieval fails
        """
        headers = {"Content-Type": "application/x-www-form-urlencoded"}
        data = {
            "grant_type": "authorization_code",
            "code": code,
            "client_id": self.client_id,
            "client_secret": self.client_secret,
            "redirect_uri": self.redirect_uri,
        }

        if code_verifier is not None:
            data["code_verifier"] = code_verifier

        response = requests.post(
            self.token_endpoint,
            data=data if self.request_type == "form_post" else None,
            params=data if self.request_type == "query" else None,
            headers=headers,
        )
        if not response.status_code == 200:
            # Try parsing JSON but fall back to text
            try:
                error_details = response.json()
            except ValueError:  # JSONDecodeError subclasses ValueError
                error_details = response.text

            logger.error(
                "Failed to retrieve ID Token",
                extra={
                    "status_code": response.status_code,
                    "url": response.url,
                    "response": error_details,
                },
            )

            raise TokenVerificationFailed(
                f"Failed to retrieve ID Token: {error_details}"
            )

        id_token = response.json().get("id_token")
        return id_token

    def _generate_pkce_code_verifier(self) -> str:
        """
        Generates a code verifier for PKCE

        https://datatracker.ietf.org/doc/html/rfc7636#section-4.1
        """
        length = self.pkce_code_verifier_length
        return secrets.token_urlsafe(length)[:length]

    def _generate_pkce_code_challenge(self, code_verifier: str) -> str:
        """
        Generates a code challenge for PKCE

        https://datatracker.ietf.org/doc/html/rfc7636#section-4.2
        """
        digest = hashlib.sha256(code_verifier.encode("ascii")).digest()
        return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")

    def login(self, redirect_after: Optional[str] = None) -> str:
        """
        Redirects the user to the authorization endpoint for Authorization
        """
        url = self.authorization_endpoint + (
            f"?client_id={self.client_id}&redirect_uri={self.redirect_uri}&"
            f"scope={self.scope}&response_type={self.response_type}&"
            f"response_mode={self.response_mode}"
        )

        if self.use_pkce:
            code_verifier = self._generate_pkce_code_verifier()
            code_challenge = self._generate_pkce_code_challenge(code_verifier)
            code_verifier_key = f"pkce_{code_challenge}"
            cache.set(
                code_verifier_key,
                code_verifier,
                self.pkce_code_challenge_timeout,
            )
            url += (
                f"&code_challenge={code_challenge}"
                f"&code_challenge_method={self.pkce_code_challenge_method}"
                f"&state={code_verifier_key}"
            )

        if self.cache_nonces or redirect_after:
            nonce = secrets.randbits(16)
            cache.set(
                nonce,
                {"auth_server": self.auth_server, "redirect_after": redirect_after},
                self.nonce_cache_timeout,
            )
            url += f"&nonce={nonce}"

        return HttpResponseRedirect(url)

    def logout(self):
        return HttpResponseRedirect(self.end_session_endpoint)
