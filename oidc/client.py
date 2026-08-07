"""
Client module for the oidc app
"""

import base64
import hashlib
import json
import logging
import secrets
from typing import Any, Callable, Mapping, Optional
from urllib.parse import quote, urlencode

from django.conf import settings
from django.core.cache import cache
from django.core.exceptions import ImproperlyConfigured
from django.http import HttpResponseRedirect

import jwt
import requests
from jwt.algorithms import RSAAlgorithm

import oidc.settings as default
from oidc.utils import str_to_bool

REDIRECT_AFTER_AUTH = "redirect_after_auth"

# Caller-supplied entries matching these keys are dropped: allowing
# overrides would let an attacker swap the redirect URI / PKCE challenge
# / state / nonce, smuggle an attacker-signed authorize request via
# ``request`` / ``request_uri`` (OIDC Core 1.0 §6), or smuggle a
# ``redirect_uris`` claim via the SIOP client-metadata channel
# (``registration`` per OIDC Core 1.0 §7.2.1; ``client_metadata`` /
# ``client_metadata_uri`` per SIOPv2).
# Characters left raw in the authorize-URL query string. ``:`` and ``/``
# keep ``redirect_uri`` values like ``http://host:port/cb`` legible in
# logs and easy to compare against IdP-side configuration.
_AUTHORIZE_URL_SAFE_CHARS = ":/"

# Cache-key prefix (`oidc:state:`) for the PKCE `state -> code_verifier`
# entry. The raw `state` value is reflected in URLs and (on the form
# re-submit path) also flows from the request body, so using it directly
# as the cache key would let any caller who reaches `_clear_login_states`
# delete arbitrary unrelated cache entries (sessions, rate-limit
# counters, etc.). Namespacing under `oidc:state:` confines those
# mutations to the OIDC keyspace.
_STATE_CACHE_PREFIX = "oidc:state:"


def state_cache_key(state: str) -> str:
    """
    Return the namespaced cache key (`oidc:state:<state>`) for an OIDC
    `state` value.

    Always use this helper when reading, writing, or deleting the
    PKCE state cache entry — never compute the key inline. The raw
    `state` value can flow from attacker-controlled request bodies
    on the form re-submit path; routing through this prefix is what
    prevents `_clear_login_states` from deleting unrelated cache
    entries (Django sessions, rate-limit counters, etc.).
    """
    return f"{_STATE_CACHE_PREFIX}{state}"


RESERVED_AUTHORIZE_PARAMS = frozenset(
    {
        "client_id",
        "redirect_uri",
        "scope",
        "response_type",
        "response_mode",
        "state",
        "nonce",
        "code_challenge",
        "code_challenge_method",
        "request",
        "request_uri",
        "registration",
        "client_metadata",
        "client_metadata_uri",
    }
)

# Caller-supplied entries matching these keys are dropped at the
# end-session URL boundary. ``client_id`` and ``post_logout_redirect_uri``
# are already baked into ``END_SESSION_ENDPOINT``; allowing overrides
# would let a query-string-tunnelled value swap the post-logout
# redirect target or impersonate a different client at the IdP.
RESERVED_END_SESSION_PARAMS = frozenset(
    {
        "client_id",
        "post_logout_redirect_uri",
    }
)

logger = logging.getLogger(__name__)


class NonceVerificationFailed(Exception):
    pass


class NoJSONWebKeyFound(Exception):
    pass


class TokenVerificationFailed(Exception):
    pass


class EndpointNotConfigured(ValueError):
    """A required ``*_ENDPOINT`` is missing for this auth server.

    Distinct from a transport failure so callers can tell "we never
    configured this" from "the IdP is down" -- ``requests`` raises
    ``JSONDecodeError``, which is *both* a ``ValueError`` and a
    ``RequestException``, so catching bare ``ValueError`` would sweep up a
    malformed IdP response and report it as our own misconfiguration.
    """


def _coerce_request_timeout(value, auth_server: str):
    """Normalise ``REQUEST_TIMEOUT`` to what ``requests`` accepts.

    A 2-item list/tuple becomes ``(connect, read)``; anything else numeric
    becomes a single float. ``None`` is rejected rather than honoured: it is
    ``requests``' "wait forever", which is the failure this setting exists
    to prevent, and accepting it silently would make an unbounded wait look
    configured on purpose.
    """
    if value is None:
        raise ImproperlyConfigured(
            f"OPENID_CONNECT_AUTH_SERVERS[{auth_server!r}]['REQUEST_TIMEOUT'] "
            f"is None, which disables the timeout entirely. Give a number of "
            f"seconds, or a (connect, read) pair."
        )
    if isinstance(value, (list, tuple)):
        if len(value) != 2:
            raise ImproperlyConfigured(
                f"OPENID_CONNECT_AUTH_SERVERS[{auth_server!r}]"
                f"['REQUEST_TIMEOUT'] must be a (connect, read) pair, got "
                f"{len(value)} item(s): {value!r}."
            )
        connect, read = value
        return (float(connect), float(read))
    return float(value)


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
        self.account_endpoint = config[auth_server].get("ACCOUNT_ENDPOINT")
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
        # ``requests`` waits forever without this, so a stalled IdP pins the
        # worker. Coerced because it accepts only a number or a 2-tuple.
        self.request_timeout = _coerce_request_timeout(
            config[auth_server].get(
                "REQUEST_TIMEOUT", default_config["REQUEST_TIMEOUT"]
            ),
            auth_server,
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
        response = requests.get(self.jwks_endpoint, timeout=self.request_timeout)
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
            self.user_info_endpoint,
            headers={"Authorization": f"Bearer {access_token}"},
            timeout=self.request_timeout,
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
        # ``login()`` writes ``{auth_server, redirect_after}`` under the
        # nonce whenever the caller supplied a ``next``, even when
        # ``USE_NONCES`` is False (line 405: ``self.cache_nonces or
        # redirect_after``). Read the cache here under the same
        # condition so the post-auth redirect honors ``next`` regardless
        # of nonce verification — otherwise the cached entry would
        # silently expire unread when ``USE_NONCES`` is False (#116).
        nonce = decoded_token.get("nonce")
        cached_data = cache.get(nonce) if nonce else None
        if self.cache_nonces:
            # Verify that the cached nonce is present and that
            # the provider the nonce was initiated for, is the same
            # provider returning it
            if not nonce:
                raise NonceVerificationFailed(
                    "Failed to verify login request. Missing nonce value"
                )
            if not cached_data or self.auth_server != cached_data.get("auth_server"):
                raise NonceVerificationFailed("Failed to verify returned nonce value")
        if cached_data and cached_data.get("redirect_after"):
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
                timeout=self.request_timeout,
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

    def login(
        self,
        redirect_after: Optional[str] = None,
        extra_params: Optional[Mapping[str, str]] = None,
    ) -> HttpResponseRedirect:
        """
        Redirects the user to the authorization endpoint for Authorization
        """
        params: list[tuple[str, Any]] = [
            ("client_id", self.client_id),
            ("redirect_uri", self.redirect_uri),
            ("scope", self.scope),
            ("response_type", self.response_type),
            ("response_mode", self.response_mode),
        ]

        if extra_params:
            params.extend(
                (key, value)
                for key, value in extra_params.items()
                if key not in RESERVED_AUTHORIZE_PARAMS
            )

        if self.use_pkce:
            code_verifier = self._generate_pkce_code_verifier()
            code_challenge = self._generate_pkce_code_challenge(code_verifier)
            # ``state`` is generated independently of ``code_challenge`` so an
            # observer of the redirect URL cannot derive one from the other.
            # The state doubles as the cache key for the verifier we'll need
            # at callback time.
            state = secrets.token_urlsafe(32)
            cache.set(
                state_cache_key(state),
                code_verifier,
                self.pkce_code_challenge_timeout,
            )
            params.extend(
                [
                    ("code_challenge", code_challenge),
                    ("code_challenge_method", self.pkce_code_challenge_method),
                    ("state", state),
                ]
            )

        if self.cache_nonces or redirect_after:
            nonce = secrets.token_urlsafe(32)
            cache.set(
                nonce,
                {"auth_server": self.auth_server, "redirect_after": redirect_after},
                self.nonce_cache_timeout,
            )
            params.append(("nonce", nonce))

        query = urlencode(params, quote_via=quote, safe=_AUTHORIZE_URL_SAFE_CHARS)
        return HttpResponseRedirect(f"{self.authorization_endpoint}?{query}")

    def logout(
        self,
        extra_params: Optional[Mapping[str, str]] = None,
    ) -> HttpResponseRedirect:
        """
        Redirects the user to the end-session endpoint for RP-initiated logout.

        ``extra_params`` is appended to the configured ``END_SESSION_ENDPOINT``
        (which already carries ``client_id`` + ``post_logout_redirect_uri``).
        Entries matching ``RESERVED_END_SESSION_PARAMS`` are silently dropped
        so callers cannot swap the values ona-oidc itself manages.

        Standard OIDC RP-Initiated Logout 1.0 hints (``id_token_hint``,
        ``logout_hint``, ``state``, ``ui_locales``) and provider-specific
        ones (``kc_idp_hint``, ``federated`` …) all flow through this
        single channel — same shape as ``login()``.
        """
        url = self.end_session_endpoint
        if not extra_params:
            return HttpResponseRedirect(url)

        filtered = [
            (key, value)
            for key, value in extra_params.items()
            if key not in RESERVED_END_SESSION_PARAMS
        ]
        if not filtered:
            return HttpResponseRedirect(url)

        separator = "&" if "?" in url else "?"
        query = urlencode(filtered, quote_via=quote, safe=_AUTHORIZE_URL_SAFE_CHARS)
        return HttpResponseRedirect(f"{url}{separator}{query}")

    def refresh_access_token(self, refresh_token: str) -> dict:
        """
        Exchange a refresh_token for a fresh token pair at the
        configured ``TOKEN_ENDPOINT``. Returns the parsed token
        response (``access_token``, ``refresh_token``, ``expires_in``,
        usually a new ``id_token`` too).

        :raises EndpointNotConfigured: ``TOKEN_ENDPOINT`` is unset.
        :raises TokenVerificationFailed: the IdP answered and refused.
        :raises requests.RequestException: the IdP could not be reached.
        """
        if not self.token_endpoint:
            raise EndpointNotConfigured(
                f"TOKEN_ENDPOINT is not configured for auth_server "
                f"{self.auth_server!r}."
            )
        headers = {"Content-Type": "application/x-www-form-urlencoded"}
        data = {
            "grant_type": "refresh_token",
            "refresh_token": refresh_token,
            "client_id": self.client_id,
            "client_secret": self.client_secret,
        }
        try:
            response = requests.post(
                self.token_endpoint,
                data=data,
                headers=headers,
                timeout=self.request_timeout,
            )
            response.raise_for_status()
        except requests.HTTPError as exc:
            # The IdP answered and refused: the refresh token is spent,
            # revoked, or issued to another client. That is a genuinely
            # dead session, so the caller turns this into a 401.
            logger.exception(exc)
            raise TokenVerificationFailed(
                f"Failed to refresh access token: {exc}"
            ) from exc
        # Transport failures (DNS, timeout) are left to propagate, as is a
        # non-JSON body. Reporting an unreachable IdP as "session expired" would
        # send the user through a re-login that cannot fix it; the proxy maps
        # RequestException to 502 instead.
        return response.json()

    def request_keycloak_account(
        self,
        access_token: str,
        method: str,
        path_suffix: str,
    ) -> tuple[int, Optional[dict]]:
        """
        Issue a generic ``method`` request to ``account_endpoint + path_suffix``
        on behalf of ``access_token``. Returns ``(status_code, body|None)``.

        This is the single entry point for every Account REST proxy call
        (sessions, linked-accounts, credentials).
        """
        if not self.account_endpoint:
            raise EndpointNotConfigured(
                f"ACCOUNT_ENDPOINT is not configured for auth_server "
                f"{self.auth_server!r}."
            )
        headers = {
            "Authorization": f"Bearer {access_token}",
            "Accept": "application/json",
        }
        url = f"{self.account_endpoint}{path_suffix}"
        try:
            response = requests.request(
                method, url, headers=headers, timeout=self.request_timeout
            )
        except requests.RequestException as exc:
            logger.exception(exc)
            raise

        body: Optional[dict] = None
        if response.content:
            try:
                body = response.json()
            except ValueError:
                body = None
        return response.status_code, body
