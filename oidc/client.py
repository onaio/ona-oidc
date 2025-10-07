"""
Client module for the oidc app
"""

import base64
import hashlib
import json
import logging
import secrets
from typing import Callable, Optional

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
        self.user_info_endpoint = config[auth_server].get("USER_INFO_ENDPOINT")
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
        self.should_verify_access_token = str_to_bool(
            config[auth_server].get(
                "VERIFY_ACCESS_TOKEN", default_config["VERIFY_ACCESS_TOKEN"]
            )
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
        self.request_mode = config[auth_server].get(
            "REQUEST_MODE", default_config["REQUEST_MODE"]
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

    def retrieve_user_info(self, access_token: str) -> dict:
        """
        Given an access_token, retrieve user profile claims
        """
        response = requests.get(
            self.user_info_endpoint, headers={"Authorization": f"Bearer {access_token}"}
        )
        return response.json()

    def get_hash_algorithm(self, alg: str) -> Optional[Callable]:
        """
        Maps JWT algorithm to hash function.

        Based on the spec: RS256/ES256/PS256 use SHA-256,
        RS384/ES384/PS384 use SHA-384, RS512/ES512/PS512 use SHA-512
        """
        algorithm_map = {
            "RS256": hashlib.sha256,
            "RS384": hashlib.sha384,
            "RS512": hashlib.sha512,
            "ES256": hashlib.sha256,
            "ES384": hashlib.sha384,
            "ES512": hashlib.sha512,
            "PS256": hashlib.sha256,
            "PS384": hashlib.sha384,
            "PS512": hashlib.sha512,
            "HS256": hashlib.sha256,
            "HS384": hashlib.sha384,
            "HS512": hashlib.sha512,
        }
        return algorithm_map.get(alg)

    def validate_access_token(
        self, decoded_id_token: dict, id_token: str, access_token: str
    ) -> bool:
        """
        Validates an access token against the at_hash claim in an ID token.

        :param decoded_id_token: A verified and decoded ID token
        :type decoded_id_token: dict
        :param id_token: The ID token (JWT) as a string
        :type id_token: string
        :param access_token: The access token to validate
        :type access_token: str

        :return bool: True if valid, False otherwise
        :raises ValueError: if algorithm in id_token header isn't supported
        """

        if "at_hash" not in decoded_id_token:
            return False

        id_token_header = jwt.get_unverified_header(id_token)
        alg_str = id_token_header.get("alg")
        hash_algorithm = self.get_hash_algorithm(alg_str)
        if not hash_algorithm:
            raise ValueError(f"Unsupported algorithm: {alg_str}")

        hash_digest = hash_algorithm(access_token.encode("ascii")).digest()
        left_half = hash_digest[: len(hash_digest) // 2]
        computed_at_hash = (
            base64.urlsafe_b64encode(left_half).decode("ascii").rstrip("=")
        )

        return computed_at_hash == decoded_id_token["at_hash"]

    def should_retrieve_user_info(self, decoded_id_token: dict) -> bool:
        if not decoded_id_token:
            return False

        return not (
            "email" in decoded_id_token
            or (
                "emails" in decoded_id_token
                and decoded_id_token["emails"]
                and decoded_id_token["emails"][0]
            )
        )

    def tokens_to_user_info(
        self,
        decoded_id_token: dict,
        id_token: Optional[str],
        access_token: Optional[str],
    ) -> dict:
        if not self.should_retrieve_user_info(decoded_id_token):
            return decoded_id_token
        if self.should_verify_access_token and not self.validate_access_token(
            decoded_id_token, id_token, access_token
        ):
            raise TokenVerificationFailed("Failed to validate access token")

        return self.retrieve_user_info(access_token)

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

    def retrieve_tokens_using_auth_code(
        self, code: str, code_verifier: Optional[str] = None
    ) -> dict:
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
        try:
            response = requests.post(
                self.token_endpoint,
                data=data if self.request_mode == "form_post" else None,
                params=data if self.request_mode == "query" else None,
                headers=headers,
            )
            response.raise_for_status()

        except requests.RequestException as exc:
            logger.exception(exc)

            raise TokenVerificationFailed(
                f"Failed to retrieve ID Token: {exc}"
            ) from exc

        return response.json()

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
