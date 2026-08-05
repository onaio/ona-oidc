from typing import Iterable, Optional
from urllib.parse import urlparse

from django.conf import settings
from django.contrib.auth import get_user_model
from django.core.exceptions import ImproperlyConfigured
from django.http import HttpRequest
from django.utils.http import url_has_allowed_host_and_scheme

import jwt
from jwt.exceptions import InvalidSignatureError

import oidc.settings as default


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
    """
    allowed_hosts = set(
        _server_setting_values(auth_server, "LOGIN_REDIRECT_ALLOWED_HOSTS")
    )
    allowed_hosts.add(request.get_host())
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


def is_allowed_account_origin(
    origin: Optional[str], auth_server: str, request: HttpRequest
) -> bool:
    """
    Whether ``origin`` (an ``Origin`` header value, ``scheme://host``) is a
    trusted first-party SPA for account-proxy calls.
    """
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
