"""
Step-up authentication: asking an identity provider to prove a stronger
factor for an action, on top of an existing session.

Kept here rather than in each consuming application because the hard parts are
identity-provider knowledge, not application policy:

* No two providers answer the same way. Keycloak emits ``acr``, WSO2 answers
  with ``amr`` (an array of executor class names, not RFC 8176 values), and
  Azure AD B2C with ``tfp`` (a user-flow name). The claim is configuration
  for that reason.
* ``acr`` on its own is session state. Measured on Keycloak 26: once a session
  has reached a level, every later authorization request for that level
  returns the claim with the ORIGINAL ``auth_time`` and prompts the user for
  nothing. Only ``max_age=0`` forces a fresh factor, which is why MAX_AGE is
  sent unconditionally and defaults to 0.

Applications keep what is theirs: which actions are gated, what to do with the
result, and how to remember that a step-up happened.
"""

import json
import logging
import math
import secrets
import time
from typing import Any, Optional, Tuple
from urllib.parse import urlencode

from django.conf import settings
from django.core.cache import cache

from oidc import settings as default_settings
from oidc.client import OpenIDClient

logger = logging.getLogger(__name__)

#: How long a step-up may stay in flight. Short, because an outstanding state
#: is a live authorisation waiting to be redeemed.
STEP_UP_STATE_TTL = 5 * 60

#: Clock skew tolerated between this server and the provider when comparing
#: ``auth_time`` with local time.
AUTH_TIME_LEEWAY_SECONDS = 60

DEFAULT_MAX_AUTH_AGE_SECONDS = 5 * 60

_STEP_UP_STATE_PREFIX = "oidc:step-up:"


def _step_up_state_key(state: str) -> str:
    """Namespaced away from the login flow's own state.

    A step-up state redeemable at the login callback -- or the reverse -- would
    let one flow's authorisation be spent by the other.
    """
    return f"{_STEP_UP_STATE_PREFIX}{state}"


def step_up_config(auth_server: str) -> dict:
    """The ``STEP_UP`` block for ``auth_server``, or ``{}``."""
    servers = getattr(settings, "OPENID_CONNECT_AUTH_SERVERS", {}) or {}
    return (servers.get(auth_server) or {}).get("STEP_UP") or {}


def step_up_redirect_uri(auth_server: str) -> Optional[str]:
    """The step-up callback, never the login one.

    The authorize request and the code exchange must carry the same value
    (RFC 6749 4.1.3), and the login callback establishes a session, so a
    step-up sent there would re-authenticate the user as a side effect.
    """
    return step_up_config(auth_server).get("REDIRECT_URI")


def find_step_up_auth_server() -> Optional[str]:
    """The first configured auth server carrying a ``STEP_UP`` block."""
    servers = getattr(settings, "OPENID_CONNECT_AUTH_SERVERS", {}) or {}
    for name, config in servers.items():
        if (config or {}).get("STEP_UP"):
            return name
    return None


def build_step_up_url(
    auth_server: str, context: Optional[dict] = None
) -> Tuple[str, str]:
    """Return ``(authorization_url, state)`` for a step-up.

    ``context`` is opaque to this module and handed back by
    :func:`redeem_step_up`. Callers use it to carry whatever the redirect
    cannot -- the provider returns to a URL, not to the control the user
    clicked.
    """
    client = OpenIDClient(auth_server)
    if not client.authorization_endpoint:
        raise ValueError(f"auth server {auth_server!r} has no AUTHORIZATION_ENDPOINT")
    config = step_up_config(auth_server)
    redirect_uri = step_up_redirect_uri(auth_server)
    if not redirect_uri:
        raise ValueError(f"auth server {auth_server!r} has no step-up REDIRECT_URI")

    verifier = client.generate_pkce_code_verifier()
    challenge = client.generate_pkce_code_challenge(verifier)
    state = _new_state()

    cache.set(
        _step_up_state_key(state),
        {
            "code_verifier": verifier,
            "context": context or {},
            # Bound so redemption exchanges against the server the flow started
            # at, not one a callback names -- see redeem_step_up.
            "auth_server": auth_server,
            "started_at": time.time(),
        },
        STEP_UP_STATE_TTL,
    )

    # Cached the way login() caches it, because verify_and_decode_id_token
    # reads it back the same way for both flows: an uncached nonce fails
    # verification for a token that is otherwise perfectly good.
    nonce = _new_state()
    if client.cache_nonces:
        cache.set(
            nonce,
            {"auth_server": auth_server, "redirect_after": None},
            client.nonce_cache_timeout,
        )

    params = {
        "client_id": client.client_id,
        "response_type": "code",
        # The provider's own scope, not a bare ``openid``: a subject check
        # needs whichever claim identifies the user, and asking for less than
        # the login flow does would strip it from the token.
        "scope": client.scope,
        "redirect_uri": redirect_uri,
        "state": state,
        "nonce": nonce,
        "code_challenge": challenge,
        "code_challenge_method": client.pkce_code_challenge_method,
        # Not optional. See the module docstring: without it the provider may
        # answer from the existing session, return the assurance claim, and
        # prompt for nothing.
        "max_age": config.get("MAX_AGE") or 0,
    }

    # acr_values is the standard request parameter (OIDC Core 3.1.2.1) and only
    # meaningful when acr is what we are going to read back. A provider keyed
    # on amr or tfp has no standard way to be asked, and is configured on its
    # own side to always emit them.
    satisfied_by = config.get("SATISFIED_BY") or []
    if satisfied_by and config.get("CLAIM") == "acr":
        params["acr_values"] = " ".join(satisfied_by)

    return f"{client.authorization_endpoint}?{urlencode(params)}", state


def redeem_step_up(
    auth_server: str, code: str, state: str
) -> Tuple[Optional[dict], dict, Optional[str]]:
    """Exchange ``code`` and return ``(claims, context, reason)``.

    ``claims`` is ``None`` with a ``reason`` -- ``state_unknown``,
    ``exchange_failed`` or ``auth_time_stale`` -- when redemption fails. The
    state is burned before the exchange, so a failure cannot be retried
    against the same authorisation.
    """
    key = _step_up_state_key(state)
    stashed = cache.get(key)
    if stashed is None:
        logger.warning("step-up: unknown or expired state")
        return None, {}, "state_unknown"
    # Delete-as-check, as spend_grant does: ``cache.delete`` reports whether it
    # removed anything, so two callbacks racing on one state cannot both go on
    # to exchange, and a burnt state cannot be retried.
    if not cache.delete(key):
        logger.warning("step-up: state already consumed")
        return None, stashed.get("context", {}), "state_unknown"

    context = stashed.get("context", {})
    # Bind the exchange to the server the flow was started against. The callback
    # names the server, but with more than one step-up server a flow begun for B
    # must not be redeemed with A's client_id/secret/endpoints.
    bound_server = stashed.get("auth_server")
    if bound_server and bound_server != auth_server:
        logger.warning("step-up: callback auth server does not match the state")
        return None, context, "state_unknown"
    auth_server = bound_server or auth_server

    try:
        # Inside the try: an unknown auth server raises from OpenIDClient, and
        # like every other exchange failure that is a refusal, not a traceback.
        client = OpenIDClient(auth_server)
        tokens = client.retrieve_tokens_using_auth_code(
            code,
            code_verifier=stashed["code_verifier"],
            redirect_uri=step_up_redirect_uri(auth_server),
        )
        claims = client.verify_and_decode_id_token(tokens.get("id_token")) or {}
    except Exception:  # noqa: BLE001
        # A provider that is down, a rejected code, a nonce that does not
        # verify: all are refusals from the caller's point of view, and none
        # should reach the user as a traceback. The state is already burnt, so
        # there is nothing to retry against.
        logger.exception("step-up: could not redeem the authorization code")
        return None, context, "exchange_failed"

    if _authenticated_before(claims, stashed.get("started_at")):
        # A provider that ignores max_age=0 answers from the existing session
        # with its original auth_time: recent, but not proved for this flow.
        logger.warning("step-up: auth_time predates the step-up request")
        return None, context, "auth_time_stale"

    return claims, context, None


def _auth_time(claims: dict) -> Optional[float]:
    try:
        auth_time = float(claims["auth_time"])
    except (KeyError, TypeError, ValueError):
        return None
    return auth_time if math.isfinite(auth_time) else None


def _authenticated_before(claims: dict, started_at: Optional[float]) -> bool:
    auth_time = _auth_time(claims)
    if auth_time is None or started_at is None:
        return False
    return auth_time < started_at - AUTH_TIME_LEEWAY_SECONDS


def _claim_matches(value: Any, accepted: set) -> bool:
    """Any-of: a list-valued claim is satisfied by any accepted member.

    A bare string is kept whole: ``set("gold")`` would match a
    single-character accepted value by accident. An unhashable value is a
    refusal, not a TypeError.
    """
    presented = value if isinstance(value, (list, tuple, set)) else [value]
    try:
        return bool(accepted.intersection(presented))
    except TypeError:
        return False


def verify_assurance(claims: dict, config: dict) -> Tuple[bool, str]:
    """``(satisfied, reason)`` for whether ``claims`` prove a fresh factor.

    Absence is never success. A token can come back valid, for the right user,
    carrying no assurance claim at all -- when the claim was requested
    voluntarily, when the provider has none configured, or when the grant type
    cannot honour it. Reading "a token came back, therefore they stepped up"
    accepts a password-only login as proof of MFA.
    """
    name = config.get("CLAIM")
    if not name:
        logger.warning("step-up: no CLAIM configured; nothing to verify")
        return False, "claim_unconfigured"
    if name not in claims:
        logger.warning("step-up: %r absent from the provider's token", name)
        return False, "claim_absent"

    accepted = set(config.get("SATISFIED_BY", ()))
    value = claims[name]
    if not _claim_matches(value, accepted):
        logger.warning("step-up: %r was %r, none of %s", name, value, sorted(accepted))
        return False, "claim_unmatched"

    # Freshness is a separate question from strength: a level can be satisfied
    # by an authentication from hours ago, which defeats step-up for revealing
    # a credential. Deployments whose provider will not return auth_time may
    # keep the prompt and forfeit the proof.
    if not config.get("REQUIRE_AUTH_TIME", True):
        return True, ""

    auth_time = _auth_time(claims)
    if auth_time is None:
        logger.warning(
            "step-up: auth_time was %r, not a timestamp", claims.get("auth_time")
        )
        return False, "auth_time_absent"
    age = time.time() - auth_time
    max_age = config.get("MAX_AUTH_AGE_SECONDS", DEFAULT_MAX_AUTH_AGE_SECONDS)
    if age > max_age or age < -AUTH_TIME_LEEWAY_SECONDS:
        return False, "auth_time_stale"
    return True, ""


def _viewset_config() -> dict:
    configured = getattr(settings, "OPENID_CONNECT_VIEWSET_CONFIG", {}) or {}
    defaults = getattr(default_settings, "OPENID_CONNECT_VIEWSET_CONFIG", {})
    return {**defaults, **configured}


def subject_binding(config: Optional[dict] = None) -> Tuple[str, str]:
    """``(claim, user_field)`` step-up should compare to identify the user.

    Defaults to whatever login already uses -- ``USER_UNIQUE_FILTER_FIELDS``
    resolved back through ``MAP_CLAIM_TO_MODEL`` -- so the two cannot disagree
    about which claim names a person. They are the same question, and a
    deployment that signed in by one claim while checking another would refuse
    every step-up as unverifiable with nothing to explain why.

    ``SUBJECT_CLAIM`` / ``SUBJECT_FIELD`` on the STEP_UP block still override,
    for providers whose step-up token carries a different claim than its
    login token.
    """
    config = config or {}
    viewset = _viewset_config()
    mapping = viewset.get("MAP_CLAIM_TO_MODEL", {}) or {}
    field_to_claim = {field: claim for claim, field in mapping.items()}

    unique_fields = viewset.get("USER_UNIQUE_FILTER_FIELDS") or ["email"]
    field = config.get("SUBJECT_FIELD") or unique_fields[0]
    claim = config.get("SUBJECT_CLAIM") or field_to_claim.get(field, field)
    return claim, field


def verify_subject(claims: dict, expected: Any, config: dict) -> Tuple[bool, str]:
    """``(satisfied, reason)`` for whether the token describes ``expected``.

    A different question from :func:`verify_assurance`: not "was a factor
    proved" but "by whom". Without it a step-up is satisfiable by signing in
    as anybody, because the state is bound to the session that started the
    flow and not to whoever finished it.

    ``expected`` is a plain value the caller reads off its own user record --
    this module deliberately does not know the user model. Matched on a
    configured claim rather than ``sub`` because applications that resolve
    accounts by username or email store no provider subject to compare.
    """
    claim, _field = subject_binding(config)
    presented = claims.get(claim)

    # Fails closed on either side being absent: a provider that omits the
    # claim, or a record with no value, must not read as "nothing to disagree
    # with, therefore it matches".
    if not presented or not expected:
        logger.warning("step-up: cannot bind the token to a user (%r claim)", claim)
        return False, "subject_unverifiable"

    if str(presented).strip().lower() != str(expected).strip().lower():
        logger.warning("step-up: token subject is not the signed-in user")
        return False, "subject_mismatch"
    return True, ""


def render_step_up_popup(
    target_origin: str, grant: Optional[str] = None, reason: Optional[str] = None
) -> str:
    """HTML that hands a step-up result to the window that opened it.

    ``target_origin`` is never ``*``: whatever the application passes back is
    a credential for the gated action, and a permissive target hands it to any
    page listening. Returns empty when no origin is configured, so a caller
    can refuse loudly rather than ship a page whose ``postMessage`` throws
    inside a popup where nobody sees it.
    """
    if not target_origin:
        return ""
    if reason:
        message = {"type": "oidc-step-up", "error": str(reason)}
    else:
        message = {"type": "oidc-step-up", "verified": True}
        if grant:
            message["grant"] = str(grant)
    # json.dumps, not HTML escaping: this is a JavaScript value, and
    # </script> in any of it would otherwise end the block early.
    payload = json.dumps(message).replace("<", "\\u003c")
    origin = json.dumps(str(target_origin)).replace("<", "\\u003c")
    return (
        "<!doctype html><title>Verification</title><script>"
        f"window.opener && window.opener.postMessage({payload}, {origin});"
        "window.close();"
        "</script><p>You can close this window.</p>"
    )


def _new_state() -> str:
    return secrets.token_urlsafe(32)


__all__ = [
    "STEP_UP_STATE_TTL",
    "build_step_up_url",
    "find_step_up_auth_server",
    "redeem_step_up",
    "render_step_up_popup",
    "step_up_config",
    "step_up_redirect_uri",
    "subject_binding",
    "verify_assurance",
    "verify_subject",
]
