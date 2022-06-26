"""
Client module for the oidc app
"""
import json
import secrets
import logging
from typing import Optional

from django.conf import settings
from django.core.cache import cache
from django.http import HttpResponseRedirect

import jwt
import requests
from jwt.algorithms import RSAAlgorithm

import oidc.settings as default
from oidc.utils import str_to_bool

config = getattr(settings, "OPENID_CONNECT_AUTH_SERVERS", {})
default_config = getattr(default, "OPENID_CONNECT_AUTH_SERVERS", {})["default"]

REDIRECT_AFTER_AUTH = "redirect_after_auth"


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
        self.auth_server = auth_server
        self.authorization_endpoint = config[auth_server].get("AUTHORIZATION_ENDPOINT")
        self.client_id = config[auth_server].get("CLIENT_ID")
        self.client_secret = config[auth_server].get("CLIENT_SECRET")
        self.jwks_endpoint = config[auth_server].get("JWKS_ENDPOINT")
        self.scope = config[auth_server].get("SCOPE") or default_config["SCOPE"]
        self.token_endpoint = config[auth_server].get("TOKEN_ENDPOINT")
        self.end_session_endpoint = config[auth_server].get("END_SESSION_ENDPOINT")
        self.redirect_uri = config[auth_server].get("REDIRECT_URI")
        self.response_type = (
            config[auth_server].get("RESPONSE_TYPE") or default_config["RESPONSE_TYPE"]
        )
        self.response_mode = (
            config[auth_server].get("RESPONSE_MODE") or default_config["RESPONSE_MODE"]
        )
        self.cache_nonces = str_to_bool(
            config[auth_server].get("USE_NONCES") or default_config["USE_NONCES"]
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

        try:
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
                if not cached_data or self.auth_server != cached_data.get(
                    "auth_server"
                ):
                    raise NonceVerificationFailed(
                        "Failed to verify returned nonce value"
                    )

                decoded_token[REDIRECT_AFTER_AUTH] = cached_data.get("redirect_after")
            return decoded_token
        except Exception as e:
            raise e

    def retrieve_token_using_auth_code(self, code: str) -> Optional[str]:
        """
        Obtain an ID Token using the Authorization Code flow
        """
        headers = {"Content-Type": "application/x-www-form-urlencoded"}
        params = {
            "grant_type": "authorization_code",
            "code": code,
            "client_id": self.client_id,
            "client_secret": self.client_secret,
            "redirect_uri": self.redirect_uri,
        }

        response = requests.post(self.token_endpoint, params=params, headers=headers)
        if not response.status_code == 200:
            raise TokenVerificationFailed(
                f"Failed to retrieve ID Token: {response.json}"
            )

        id_token = response.json().get("id_token")
        return id_token

    def login(self, redirect_after: Optional[str] = None) -> str:
        """
        Redirects the user to the authorization endpoint for Authorization
        """
        url = self.authorization_endpoint + (
            f"?client_id={self.client_id}&redirect_uri={self.redirect_uri}&"
            f"scope={self.scope}&response_type={self.response_type}&"
            f"response_mode={self.response_mode}"
        )
        if self.cache_nonces or redirect_after:
            nonce = secrets.randbits(16)
            cache.set(
                nonce,
                {"auth_server": self.auth_server, "redirect_after": redirect_after},
            )
            url += f"&nonce={nonce}"

        return HttpResponseRedirect(url)

    def logout(self):
        return HttpResponseRedirect(self.end_session_endpoint)
