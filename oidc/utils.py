from django.conf import settings
from django.contrib.auth import get_user_model

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


def get_login_query_param_allowlist(auth_server: str) -> frozenset:
    """
    Return the set of query parameter names that the login view is allowed to
    forward to the configured authorization endpoint for ``auth_server``.

    Configured per auth server via
    ``OPENID_CONNECT_AUTH_SERVERS[<server>]["LOGIN_QUERY_PARAM_ALLOWLIST"]``.
    Defaults to an empty set so unknown query params are dropped at the
    viewset boundary.
    """
    config = getattr(settings, "OPENID_CONNECT_AUTH_SERVERS", {})
    server_config = config.get(auth_server) or {}
    return frozenset(server_config.get("LOGIN_QUERY_PARAM_ALLOWLIST", ()))
