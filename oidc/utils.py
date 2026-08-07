import logging
from typing import Iterable, Optional
from urllib.parse import urlparse

from django.conf import settings
from django.contrib.auth import get_user_model
from django.core.exceptions import DisallowedHost, ImproperlyConfigured
from django.http import HttpRequest
from django.utils.http import url_has_allowed_host_and_scheme

import jwt
from jwt.exceptions import InvalidSignatureError

import oidc.settings as default

logger = logging.getLogger(__name__)


def authenticate_sso(request, unique_user_field: str = "email"):
    config = getattr(settings, "OPENID_CONNECT_VIEWSET_CONFIG", {})
    secret_key = config.get("JWT_SECRET_KEY", "")
    algorithm = config.get("JWT_ALGORITHM", "HS256")
    sso = request.META.get("HTTP_SSO") or request.COOKIES.get("SSO")
    if not sso:
        return None

    try:
        jwt_payload = jwt.decode(sso, secret_key, algorithms=[algorithm])
        unique_user_value = jwt_payload.get(unique_user_field)
        if unique_user_value is None and unique_user_field != "email":
            # Older SSO cookies always used the "email" claim name, even when
            # SSO_COOKIE_DATA pointed at a different user model field.
            unique_user_value = jwt_payload.get("email")
        if unique_user_value is None:
            return None
        user = (
            get_user_model()
            .objects.filter(**{unique_user_field: unique_user_value})
            .first()
        )
        if user and user.is_active:
            return (user, True)
    except InvalidSignatureError:
        pass
    return None


def str_to_bool(val):
    if isinstance(val, str):
        val = 0 if val == "False" else 1
    return val


def email_usename_to_url_safe(email_username):
    return email_username.split("@")[0]


def replace_characters_in_username(
    username, replace_username_characters, username_char_replacement
):
    if replace_username_characters and username_char_replacement is not None:
        for char in list(replace_username_characters):
            username = username.replace(char, username_char_replacement)
    return username


def get_viewset_config():
    default_config = getattr(default, "OPENID_CONNECT_VIEWSET_CONFIG", {})
    return getattr(settings, "OPENID_CONNECT_VIEWSET_CONFIG", default_config)


#: Base names of the OIDC tokens ``callback`` stashes in the Django session.
#: Never used as session keys directly — see ``token_session_key``.
ACCESS_TOKEN_SESSION_KEY = "oidc_access_token"
REFRESH_TOKEN_SESSION_KEY = "oidc_refresh_token"
ID_TOKEN_SESSION_KEY = "oidc_id_token"


def token_session_key(base_key: str, auth_server: Optional[str]) -> str:
    """Session key for ``base_key``, namespaced to the issuing ``auth_server``.

    The URL selects the provider while the session holds the tokens, so a
    global key would let a request to provider B spend provider A's tokens
    against B's endpoints. Namespacing makes that unrepresentable: B's slot
    is simply empty, which callers already treat as "no session".

    No fallback to the un-namespaced key — reading it would reinstate the
    path this closes. Older sessions take one 401 and sign in again.
    """
    return f"{base_key}:{auth_server}"


#: The three slots ``callback`` fills and ``logout`` clears, in one place so
#: the two cannot drift.
TOKEN_SESSION_BASE_KEYS = (
    ACCESS_TOKEN_SESSION_KEY,
    REFRESH_TOKEN_SESSION_KEY,
    ID_TOKEN_SESSION_KEY,
)


def pending_token_session_key(base_key: str, auth_server: Optional[str]) -> str:
    """Session key for a token parked across the username-form round trip.

    Used by that flow alone: the form re-POSTs only the ``id_token``, so the
    pair the first request obtained has to survive until the resubmit. Every
    other path writes the active slots directly on success, which is what
    keeps a refused caller from leaving a refresh token at rest.
    """
    return f"{token_session_key(base_key, auth_server)}:pending"


def stash_pending_tokens(
    session,
    auth_server: Optional[str],
    id_token: Optional[str],
    access_token: Optional[str],
    refresh_token: Optional[str],
) -> None:
    """Park a token pair for the username-form round trip.

    ``id_token`` is stored alongside as the pair's owner; see
    ``take_pending_tokens``. All three slots are written as a unit, clearing
    rather than skipping an absent value — otherwise a flow with no refresh
    token would inherit the previous flow's under its own owner tag.
    """
    if session is None or not access_token:
        return
    for base_key, value in (
        (ID_TOKEN_SESSION_KEY, id_token),
        (ACCESS_TOKEN_SESSION_KEY, access_token),
        (REFRESH_TOKEN_SESSION_KEY, refresh_token),
    ):
        key = pending_token_session_key(base_key, auth_server)
        if value:
            session[key] = value
        else:
            session.pop(key, None)


def take_pending_tokens(session, auth_server: Optional[str], id_token: Optional[str]):
    """Pop the parked pair, but only if it belongs to ``id_token``.

    One session can be running two logins at once (two tabs), and both write
    the same per-provider slots. Pairing one login's id_token with another's
    tokens would sign the browser in as one identity while the proxy acted
    on the other's Keycloak account, so a mismatch is dropped rather than
    used. Drains all three slots either way, which also clears the pair left
    by a login abandoned at the form.

    Returns ``(access_token, refresh_token)``, either of which may be None.
    """
    if session is None:
        return None, None
    owner = session.pop(
        pending_token_session_key(ID_TOKEN_SESSION_KEY, auth_server), None
    )
    access_token = session.pop(
        pending_token_session_key(ACCESS_TOKEN_SESSION_KEY, auth_server), None
    )
    refresh_token = session.pop(
        pending_token_session_key(REFRESH_TOKEN_SESSION_KEY, auth_server), None
    )
    if not owner or owner != id_token or not access_token:
        # A lone refresh token is never usable on its own, and handing one
        # back would write an active refresh with no matching access token.
        return None, None
    return access_token, refresh_token


def _coerce_string_iterable(value, key: str, auth_server: str) -> Iterable[str]:
    """Reject string configs for list-typed settings.

    Without this, ``"prompt"`` (a common typo for ``["prompt"]``) silently
    iterates as characters and produces a junk allowlist / hosts set.
    """
    if isinstance(value, str):
        raise ImproperlyConfigured(
            f"OPENID_CONNECT_AUTH_SERVERS[{auth_server!r}][{key!r}] must be "
            f"a list/tuple of strings, got a single string {value!r}. "
            f"Did you mean [{value!r}]?"
        )
    return value


def _server_setting_values(auth_server: str, key: str) -> Iterable[str]:
    """Validated string values of ``key`` for ``auth_server``; empty when unset.

    Keeps ``key`` named once per call site — it is otherwise repeated as both
    the lookup and the error label, which drift apart under rename.
    """
    config = getattr(settings, "OPENID_CONNECT_AUTH_SERVERS", {})
    server_config = config.get(auth_server, {})
    return _coerce_string_iterable(server_config.get(key, ()), key, auth_server)


def get_login_query_param_allowlist(auth_server: str) -> frozenset[str]:
    """
    Return the set of query parameter names that the login view is allowed to
    forward to the configured authorization endpoint for ``auth_server``.

    Configured per auth server via
    ``OPENID_CONNECT_AUTH_SERVERS[<server>]["LOGIN_QUERY_PARAM_ALLOWLIST"]``.
    Defaults to an empty set so unknown query params are dropped at the
    viewset boundary.
    """
    return frozenset(_server_setting_values(auth_server, "LOGIN_QUERY_PARAM_ALLOWLIST"))


def get_logout_query_param_allowlist(auth_server: str) -> frozenset[str]:
    """
    Return the set of query parameter names that the logout view is allowed to
    forward to the configured end-session endpoint for ``auth_server``.

    Configured per auth server via
    ``OPENID_CONNECT_AUTH_SERVERS[<server>]["LOGOUT_QUERY_PARAM_ALLOWLIST"]``.
    Defaults to an empty set so unknown query params are dropped at the
    viewset boundary — matches the ``LOGIN_QUERY_PARAM_ALLOWLIST`` shape.
    """
    return frozenset(
        _server_setting_values(auth_server, "LOGOUT_QUERY_PARAM_ALLOWLIST")
    )


def _trusted_spa_hosts(auth_server: str, request: HttpRequest) -> set:
    """Hosts trusted as the first-party SPA for ``auth_server``.

    The request's own host plus any listed in
    ``OPENID_CONNECT_AUTH_SERVERS[<server>]["LOGIN_REDIRECT_ALLOWED_HOSTS"]``.
    One definition of "our SPA", reused by the login-redirect and the
    account-proxy origin checks so they can't drift.

    The own-host entry is a convenience so same-origin deployments need no
    extra config. When the Host header isn't one Django will vouch for,
    ``get_host()`` raises and we simply leave it out: the configured
    allowlist is the static trust root and stands on its own, so a caller
    with a forged Host is judged against that alone rather than crashing
    the check.
    """
    allowed_hosts = set(
        _server_setting_values(auth_server, "LOGIN_REDIRECT_ALLOWED_HOSTS")
    )
    try:
        allowed_hosts.add(request.get_host())
    except DisallowedHost:
        logger.warning(
            "Host header rejected by ALLOWED_HOSTS; judging %r against the "
            "configured allowlist only.",
            auth_server,
        )
    return allowed_hosts


def is_safe_login_redirect(
    url: Optional[str], auth_server: str, request: HttpRequest
) -> bool:
    """
    Whether ``url`` is safe to use as a post-authentication redirect target.

    Path-only URLs are always accepted. Absolute URLs must point at the
    request's own host or one of the hostnames listed in
    ``OPENID_CONNECT_AUTH_SERVERS[<server>]["LOGIN_REDIRECT_ALLOWED_HOSTS"]``.
    The default empty allowlist + the request host gives same-origin
    deployments zero-config safety; cross-origin SPAs opt in by listing
    their host explicitly.

    Wraps Django's ``url_has_allowed_host_and_scheme`` so disallowed
    schemes (``javascript:``, ``data:`` …) and protocol-relative
    ``//attacker`` URLs are rejected.
    """
    if not url:
        return False
    return url_has_allowed_host_and_scheme(
        url,
        allowed_hosts=_trusted_spa_hosts(auth_server, request),
        require_https=request.is_secure(),
    )


def is_allowed_account_origin(auth_server: str, request: HttpRequest) -> bool:
    """
    Whether ``request``'s ``Origin`` header is a trusted first-party SPA for
    account-proxy calls. A missing ``Origin`` is allowed — same-origin
    requests may omit it, and the custom-header requirement still gates those.
    """
    origin = request.headers.get("Origin")
    if not origin:
        return True

    # Require an explicit scheme + host.
    parsed = urlparse(origin)
    if not parsed.scheme or not parsed.netloc:
        return False

    return url_has_allowed_host_and_scheme(
        origin,
        allowed_hosts=_trusted_spa_hosts(auth_server, request),
        require_https=request.is_secure(),
    )
