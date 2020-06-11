"""
Client module for the OICD app
"""
import json
import secrets
from typing import Optional

import jwt
import requests
from django.conf import settings
from django.core.cache import cache
from django.http import HttpResponseRedirect
from jwt.algorithms import RSAAlgorithm

import oicd.settings as default

config = getattr(settings, "OPENID_CONNECT_AUTH_SERVERS", {})
default_config = getattr(default, "OPENID_CONNECT_AUTH_SERVERS", {})["default"]


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
        self.cache_nonces = (
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

        if jwks:
            alg = unverified_header.get("alg")
            public_key = RSAAlgorithm.from_jwk(json.dumps(jwks))

            try:
                decoded_token = jwt.decode(
                    id_token, public_key, audience=[self.client_id], algorithms=alg
                )

                if self.cache_nonces:
                    # Verify that the cached nonce is present and that
                    # the provider the nonce was initiated for, is the same
                    # provider returning it
                    server = cache.get(decoded_token.get("nonce"))
                    if self.auth_server != server:
                        return None

                return decoded_token
            except Exception as e:
                raise e
        return None

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
        if response.status_code == 200:
            id_token = response.json().get("id_token")
            return id_token
        return None

    def login(self) -> str:
        """
        Redirects the user to the authorization endpoint for Authorization
        """
        url = self.authorization_endpoint + (
            f"?client_id={self.client_id}&redirect_uri={self.redirect_uri}&"
            f"scope={self.scope}&response_type={self.response_type}&"
            f"response_mode={self.response_mode}"
        )
        if self.cache_nonces:
            nonce = secrets.randbits(16)
            cache.set(nonce, self.auth_server)
            url += f"&nonce={nonce}"
        return HttpResponseRedirect(url)

    def logout(self):
        return HttpResponseRedirect(self.end_session_endpoint)
