"""
Client module for the oidc app
"""

import base64
import hashlib
import json
import logging
import re
import secrets
from typing import Any, Callable, Mapping, Optional
from urllib.parse import quote, urlencode

from django.conf import settings
from django.core.cache import DEFAULT_CACHE_ALIAS, cache
from django.core.cache.backends.dummy import DummyCache
from django.core.cache.backends.filebased import FileBasedCache
from django.core.exceptions import ImproperlyConfigured
from django.http import HttpResponseRedirect
from django.utils.module_loading import import_string
from django.views.decorators.debug import sensitive_variables

import jwt
import requests
from jwt.algorithms import RSAAlgorithm

import oidc.settings as default
from oidc.utils import has_email_address, parse_requests_timeout, str_to_bool

REDIRECT_AFTER_AUTH = "redirect_after_auth"
REQUEST_MODES = ("form_post", "query")

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


# Login bindings (RFC 9700 §4.4, login CSRF). Each browser carries a
# random identifier in an HttpOnly cookie, one per response mode. A
# login start records its state's digest in the shared cache under
# that identifier, and the callback requires the echoed state to be
# recorded for the identifier the browser sends, before it consults
# any other cache entry. Starts racing on the same jar carry the same
# identifier, so the order their responses land in does not matter.
_LOGIN_BROWSER_COOKIE_PREFIX = "oidc_login_browser_"
# Must outlive the longest time a user plausibly leaves the IdP page
# open; the state/nonce cache TTLs end a flow earlier anyway.
LOGIN_BINDING_MAX_AGE = 1800
# The most pending logins one browser can have per response mode. A
# start beyond it is refused, so a page cannot grow a browser's
# bindings without bound. Six leaves room for every login a user
# plausibly keeps open at once.
LOGIN_BINDING_SLOTS = 6
# How long a slot hand-off key lives. A start writes the slot right
# after taking the hand-off, so the key only has to outlast that.
_LOGIN_BINDING_HANDOFF_TTL = 60


def _state_digest(state: str) -> str:
    return hashlib.sha256(state.encode("utf-8")).hexdigest()


def login_browser_cookie_name(response_mode: str) -> str:
    """
    Return the name of the cookie carrying the browser identifier for
    logins in ``response_mode``.

    Each mode gets its own cookie, so a query-mode start never
    rewrites the SameSite=None cookie that form_post logins need.
    """
    return f"{_LOGIN_BROWSER_COOKIE_PREFIX}{response_mode}"


# secrets.token_urlsafe(32): 43 characters of the URL-safe alphabet.
_LOGIN_BROWSER_ID_PATTERN = re.compile(r"[A-Za-z0-9_-]{43}")


def login_browser_id(cookies: Mapping[str, str], response_mode: str) -> Optional[str]:
    """
    Return the browser identifier carried for ``response_mode``, or
    None when the browser has none or the value is malformed.
    """
    value = cookies.get(login_browser_cookie_name(response_mode))
    if isinstance(value, str) and _LOGIN_BROWSER_ID_PATTERN.fullmatch(value):
        return value
    return None


def mint_login_browser_id() -> str:
    """Return a new random browser identifier."""
    return secrets.token_urlsafe(32)


def _login_binding_namespace(browser_id: str) -> str:
    return f"oidc:login-binding:{_state_digest(browser_id)[:32]}"


def _login_binding_key(browser_id: str, digest: str) -> str:
    # One record per login: the state digest makes the key unique to
    # its binding, so deleting it can never remove another login's.
    return f"{_login_binding_namespace(browser_id)}:{digest}"


def claim_login_binding(browser_id: str, state: str) -> bool:
    """
    Bind ``state`` to the browser identified by ``browser_id``.

    Returns False, binding nothing, when the browser already has
    ``LOGIN_BINDING_SLOTS`` pending logins.
    """
    digest = _state_digest(state)
    key = _login_binding_key(browser_id, digest)
    # add() rather than set(): the key is unique to this login, so
    # False can only mean the write failed, which some backends (the
    # database cache) report no other way.
    if not cache.add(key, True, LOGIN_BINDING_MAX_AGE):
        return False
    namespace = _login_binding_namespace(browser_id)
    for slot in range(LOGIN_BINDING_SLOTS):
        slot_key = f"{namespace}:slot:{slot}"
        if cache.add(slot_key, digest, LOGIN_BINDING_MAX_AGE):
            return True
        holder = cache.get(slot_key)
        if not isinstance(holder, str):
            continue
        if cache.get(_login_binding_key(browser_id, holder)) is not None:
            continue
        # The holder's login finished or expired, and its record never
        # comes back, so the slot is free. The hand-off key names the
        # holder, so exactly one start can take this slot over.
        if cache.add(f"{slot_key}:after:{holder}", True, _LOGIN_BINDING_HANDOFF_TTL):
            cache.set(slot_key, digest, LOGIN_BINDING_MAX_AGE)
            return True
    cache.delete(key)
    return False


def has_login_binding(browser_id: Optional[str], state: Optional[str]) -> bool:
    """
    Whether the browser identified by ``browser_id`` started the login
    that minted ``state``.

    A missing identifier, or a non-string ``state`` from a malformed
    callback body, matches nothing and never raises.
    """
    if not browser_id or not state or not isinstance(state, str):
        return False
    key = _login_binding_key(browser_id, _state_digest(state))
    return cache.get(key) is not None


def release_login_binding(browser_id: Optional[str], state: Optional[str]) -> None:
    """
    End the binding of ``state`` to the browser identified by
    ``browser_id`` once its login has finished.

    Only this login's own record is deleted; its key is unique to the
    state, so a delayed call never removes another login's binding.
    """
    if not browser_id or not state or not isinstance(state, str):
        return
    cache.delete(_login_binding_key(browser_id, _state_digest(state)))


# Backends that cannot hold login bindings: the dummy cache stores
# nothing, and the file cache is local to one host and its add() is a
# separate check and write.
_UNSUPPORTED_LOGIN_BINDING_CACHES = (DummyCache, FileBasedCache)


def check_login_binding_cache() -> None:
    """
    Raise ImproperlyConfigured when any configured auth server enforces
    browser binding and the default cache cannot hold the bindings.

    Bindings need a cache that every worker shares and whose ``add``
    is atomic, such as Redis, Memcached or the database cache.
    """
    default_config = getattr(default, "OPENID_CONNECT_AUTH_SERVERS", {})["default"]
    servers = getattr(settings, "OPENID_CONNECT_AUTH_SERVERS", {})
    enforced = any(
        str_to_bool(
            config.get(
                "ENFORCE_BROWSER_BINDING",
                default_config["ENFORCE_BROWSER_BINDING"],
            )
        )
        for config in servers.values()
    )
    backend_path = settings.CACHES[DEFAULT_CACHE_ALIAS]["BACKEND"]
    if enforced and issubclass(
        import_string(backend_path), _UNSUPPORTED_LOGIN_BINDING_CACHES
    ):
        raise ImproperlyConfigured(
            "ENFORCE_BROWSER_BINDING needs a cache shared by every worker "
            "with an atomic add(), such as Redis, Memcached or the "
            f"database cache; the default cache is {backend_path}."
        )


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

# Signature algorithms a configured ``ID_TOKEN_ALLOWED_ALGORITHMS``
# list may contain. All are RSA-key algorithms, matching the RSA-only
# JWKS handling in ``verify_and_decode_id_token``; the token's own
# ``alg`` header never selects the verification algorithm.
ID_TOKEN_SUPPORTED_ALGORITHMS = frozenset(
    {"RS256", "RS384", "RS512", "PS256", "PS384", "PS512"}
)

logger = logging.getLogger(__name__)


ID_TOKEN_LEEWAY_SECONDS = 30


class NonceVerificationFailed(Exception):
    pass


class NoJSONWebKeyFound(Exception):
    pass


class TokenVerificationFailed(Exception):
    pass


class UserInfoRequestFailed(Exception):
    pass


def _describe_token_failure(
    response: Optional[requests.Response], failure_type: Optional[str]
) -> str:
    """
    Summarise a failed token request for the log message.

    Returns the HTTP status and what went wrong, never response or exception
    text. Providers can echo the request, client secret included, into their
    error fields.
    """
    if response is None:
        return failure_type or "no response"
    return " ".join(filter(None, [f"HTTP {response.status_code}", failure_type]))


def _token_response_details(response: requests.Response) -> dict:
    """
    Describe an unusable token response for error reporting.

    Leaves out the body: a provider can echo the client secret in any
    encoding, so no redaction can be trusted to catch it.
    """
    return {
        "status_code": response.status_code,
        "content_type": response.headers.get("Content-Type"),
        "body_length": len(response.text),
    }


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
        self.enforce_browser_binding = str_to_bool(
            config[auth_server].get(
                "ENFORCE_BROWSER_BINDING",
                default_config["ENFORCE_BROWSER_BINDING"],
            )
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
        # The cache treats 0 or less as already expired.
        if self.nonce_cache_timeout <= 0:
            raise ImproperlyConfigured(
                f"OPENID_CONNECT_AUTH_SERVERS[{auth_server!r}]"
                "['NONCE_CACHE_TIMEOUT'] must be positive, "
                f"got {self.nonce_cache_timeout}"
            )
        self.requests_timeout = parse_requests_timeout(
            config[auth_server].get(
                "REQUESTS_TIMEOUT", default_config["REQUESTS_TIMEOUT"]
            ),
            f"OPENID_CONNECT_AUTH_SERVERS[{auth_server!r}]['REQUESTS_TIMEOUT']",
        )
        self.require_verified_email = str_to_bool(
            config[auth_server].get(
                "REQUIRE_VERIFIED_EMAIL", default_config["REQUIRE_VERIFIED_EMAIL"]
            )
        )
        check_email_verified = str_to_bool(
            config[auth_server].get(
                "CHECK_EMAIL_VERIFIED", default_config["CHECK_EMAIL_VERIFIED"]
            )
        )
        self.check_email_verified = bool(
            self.require_verified_email or check_email_verified
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
        # Any other value would send the token request with no credentials.
        if self.request_mode not in REQUEST_MODES:
            raise ImproperlyConfigured(
                f"REQUEST_MODE must be one of {REQUEST_MODES}, "
                f"got {self.request_mode!r}"
            )
        # Normalized to None so every falsy value means "no iss check";
        # PyJWT itself only skips the check for None, and would enforce
        # iss == "" for an empty string.
        self.issuer = config[auth_server].get("ISSUER") or None
        allowed_algorithms = config[auth_server].get(
            "ID_TOKEN_ALLOWED_ALGORITHMS",
            default_config["ID_TOKEN_ALLOWED_ALGORITHMS"],
        )
        # A bare string would hit PyJWT's substring matching, and a
        # non-RSA entry would send that token's verification down a
        # code path our RSA-only JWKS handling cannot satisfy, raising
        # an exception the callback does not treat as a rejection.
        if (
            not isinstance(allowed_algorithms, (list, tuple))
            or not allowed_algorithms
            or not set(allowed_algorithms) <= ID_TOKEN_SUPPORTED_ALGORITHMS
        ):
            raise ImproperlyConfigured(
                f"OPENID_CONNECT_AUTH_SERVERS[{auth_server!r}]"
                "['ID_TOKEN_ALLOWED_ALGORITHMS'] must be a non-empty list "
                f"drawn from {sorted(ID_TOKEN_SUPPORTED_ALGORITHMS)}"
            )
        self.id_token_allowed_algorithms = list(allowed_algorithms)
        self.verify_authorized_party = str_to_bool(
            config[auth_server].get(
                "ID_TOKEN_VERIFY_AZP", default_config["ID_TOKEN_VERIFY_AZP"]
            )
        )
        self.require_subject = str_to_bool(
            config[auth_server].get(
                "ID_TOKEN_REQUIRE_SUB", default_config["ID_TOKEN_REQUIRE_SUB"]
            )
        )

    def _retrieve_jwks_related_to_kid(self, kid: str) -> Optional[str]:
        """
        Retrieves a JSON Web Key Set that can be used to verify a
        JSON web token issued by an authentication server.
        """
        try:
            response = requests.get(self.jwks_endpoint, timeout=self.requests_timeout)
        except requests.RequestException as exc:
            raise NoJSONWebKeyFound(
                f"JWKS request failed: {type(exc).__name__}"
            ) from exc
        if response.status_code == 200:
            jwks = response.json()
            for jwk in jwks.get("keys"):
                if jwk.get("kid") == kid:
                    return jwk
        return None

    def retrieve_user_info(self, access_token: str) -> dict:
        """
        Given an access_token, retrieve user profile claims

        :raises UserInfoRequestFailed: if the request fails, gets an error
            status, or gets a body that is not JSON
        """
        try:
            response = requests.get(
                self.user_info_endpoint,
                headers={"Authorization": f"Bearer {access_token}"},
                timeout=self.requests_timeout,
            )
        except requests.RequestException as exc:
            raise UserInfoRequestFailed(
                f"Userinfo request failed: {type(exc).__name__}"
            ) from exc
        if not 200 <= response.status_code < 300:
            raise UserInfoRequestFailed(
                f"Userinfo request failed: status {response.status_code}"
            )
        try:
            return response.json()
        except ValueError as exc:
            raise UserInfoRequestFailed("Userinfo response is not JSON") from exc

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

        return not has_email_address(decoded_id_token)

    def tokens_to_user_info(
        self,
        decoded_id_token: dict,
        id_token: Optional[str],
        access_token: Optional[str],
    ) -> dict:
        if not self.should_retrieve_user_info(decoded_id_token):
            return decoded_id_token
        if self.should_verify_access_token:
            self._verify_access_token(decoded_id_token, id_token, access_token)

        return self.retrieve_user_info(access_token)

    def _verify_access_token(
        self,
        decoded_id_token: dict,
        id_token: Optional[str],
        access_token: Optional[str],
    ) -> None:
        """Raise ``TokenVerificationFailed`` unless the access token
        matches ``at_hash``."""
        if not access_token:
            raise TokenVerificationFailed(
                "Failed to validate access token: no access token"
            )
        if not isinstance(access_token, str):
            raise TokenVerificationFailed(
                "Failed to validate access token: cannot compute at_hash"
            )
        try:
            matches = self.validate_access_token(
                decoded_id_token, id_token, access_token
            )
        except ValueError:
            # A non-ASCII access token raises UnicodeEncodeError, which holds
            # the whole token. Raising outside this block keeps it off the
            # exception chain that error reporters record.
            matches = None
        if matches is None:
            raise TokenVerificationFailed(
                "Failed to validate access token: cannot compute at_hash"
            )
        if not matches:
            # The spec lets an IdP omit at_hash in the code flow. Setting
            # VERIFY_ACCESS_TOKEN=False fixes that case but not a mismatch.
            # The logged reason names the case so an operator can tell.
            reason = (
                "at_hash does not match"
                if "at_hash" in decoded_id_token
                else "ID token has no at_hash"
            )
            raise TokenVerificationFailed(f"Failed to validate access token: {reason}")

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

        try:
            public_key = RSAAlgorithm.from_jwk(json.dumps(jwks))
        except jwt.exceptions.InvalidKeyError as exc:
            # The kid matched a JWKS entry that is not an RSA key (EC,
            # OKP, …). InvalidKeyError is not an InvalidTokenError, so
            # without this translation it would escape the callback's
            # handled-rejection path as a server error.
            raise NoJSONWebKeyFound(
                "ID token key is not usable with the allowed RSA algorithms"
            ) from exc
        cached_data = {}

        if not self.issuer:
            logger.warning(
                "No ISSUER configured for auth server %r; the ID token's "
                "iss claim is not verified. Set OPENID_CONNECT_AUTH_SERVERS"
                "[%r]['ISSUER'] to the provider's issuer URL.",
                self.auth_server,
                self.auth_server,
            )
        decoded_token = jwt.decode(
            id_token,
            public_key,
            audience=[self.client_id],
            issuer=self.issuer,
            algorithms=self.id_token_allowed_algorithms,
            options={"require": self._required_id_token_claims()},
            # Tolerate small IdP/server clock skew: with iat required,
            # PyJWT otherwise rejects a token whose iat is seconds ahead
            # as "not yet valid".
            leeway=ID_TOKEN_LEEWAY_SECONDS,
        )
        if self.verify_authorized_party:
            self._verify_authorized_party(decoded_token)
        # ``login()`` caches ``{auth_server, redirect_after}`` under the
        # nonce whenever the caller passes ``next``, even when
        # ``USE_NONCES`` is False. Consume it in both modes so the
        # post-auth redirect honors ``next`` (#116).
        nonce = decoded_token.get("nonce")
        cached_data = self._consume_nonce(nonce) if nonce else None
        if self.cache_nonces:
            # Verify that the cached nonce is present and that
            # the provider the nonce was initiated for, is the same
            # provider returning it
            if not nonce:
                raise NonceVerificationFailed(
                    "Failed to verify login request. Missing nonce value"
                )
            if cached_data is None:
                raise NonceVerificationFailed("Failed to verify returned nonce value")
        if cached_data and cached_data.get("redirect_after"):
            decoded_token[REDIRECT_AFTER_AUTH] = cached_data.get("redirect_after")
        return decoded_token

    def _required_id_token_claims(self) -> list[str]:
        claims = ["exp", "iat", "aud"]
        return [*claims, "sub"] if self.require_subject else claims

    def _verify_authorized_party(self, decoded_token: dict) -> None:
        """
        Check ``azp`` on a token with several distinct audiences.

        PyJWT accepts a token when this client is any one of its audiences.
        A token with other audiences too must name this client in ``azp``,
        or it was issued to another client. A token for this client alone
        is not checked, because some providers set ``azp`` to a different
        client on it.

        :raises jwt.MissingRequiredClaimError: when ``azp`` is missing.
        :raises jwt.InvalidAudienceError: when ``azp`` names another client.
        """
        audience = decoded_token.get("aud")
        if not isinstance(audience, list) or len(set(audience)) < 2:
            return
        if "azp" not in decoded_token:
            raise jwt.MissingRequiredClaimError("azp")
        if decoded_token["azp"] != self.client_id:
            raise jwt.InvalidAudienceError("Authorized party is not this client")

    def _consume_nonce(self, nonce: str) -> Optional[dict]:
        """
        Return and delete the login data ``login()`` cached under
        ``nonce`` for this provider, or None.

        A nonce is single-use (OIDC Core 1.0 §15.5.2): only the request
        whose delete removes the entry gets it, so concurrent replays of
        one ID token cannot both pass. The nonce is echoed back by the
        IdP and can name any cache key, so entries ``login()`` did not
        write for this provider are left alone.
        """
        cached_data = cache.get(nonce)
        if (
            not isinstance(cached_data, dict)
            or cached_data.get("auth_server") != self.auth_server
            or not cache.delete(nonce)
        ):
            return None
        return cached_data

    # A bare sensitive_variables() hides every local here and in the frames this
    # calls. A list of names would miss values that callees hold under other
    # names, and locals added later.
    @sensitive_variables()
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
        response = None
        failure_type = None
        try:
            response = requests.post(
                self.token_endpoint,
                data=data if self.request_mode == "form_post" else None,
                params=data if self.request_mode == "query" else None,
                headers=headers,
                timeout=self.requests_timeout,
            )
            response.raise_for_status()
            tokens = response.json()
        except requests.HTTPError:
            pass  # The status code already says what failed.
        except (requests.RequestException, ValueError, RecursionError) as exc:
            failure_type = type(exc).__name__
        else:
            if isinstance(tokens, dict):
                return tokens
            failure_type = "non-object JSON"

        # Raise outside the except block, so nothing raised here chains the
        # original exception, whose text may include the request URL.
        extra = None
        if response is not None:
            extra = {"token_response": _token_response_details(response)}
        logger.error(
            "Token request failed: %s",
            _describe_token_failure(response, failure_type),
            extra=extra,
        )
        raise TokenVerificationFailed("Failed to retrieve ID Token")

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
        else:
            # The IdP echoes state back verbatim in every response
            # mode, so the callback can bind the authorization response
            # to the browser that started the login. Without PKCE
            # nothing is cached under it.
            params.append(("state", secrets.token_urlsafe(32)))

        if self.cache_nonces or redirect_after:
            nonce = secrets.token_urlsafe(32)
            cache.set(
                nonce,
                {"auth_server": self.auth_server, "redirect_after": redirect_after},
                self.nonce_cache_timeout,
            )
            params.append(("nonce", nonce))

        query = urlencode(params, quote_via=quote, safe=_AUTHORIZE_URL_SAFE_CHARS)
        response = HttpResponseRedirect(f"{self.authorization_endpoint}?{query}")
        # The redirect is specific to one browser. Its state, and the
        # binding cookie the viewset adds, must never come out of a
        # shared cache into another browser.
        response["Cache-Control"] = "no-store"
        return response

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
