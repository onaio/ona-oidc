from django.conf import settings
from django.contrib.auth import get_user_model

import jwt


def authenticate_sso(request, unique_user_field: str = "email"):
    config = getattr(settings, "OPENID_CONNECT_VIEWSET_CONFIG", {})
    secret_key = config.get("JWT_SECRET_KEY", "")
    algorithm = config.get("JWT_ALGORITHM", "HS256")
    sso = request.META.get("HTTP_SSO") or request.COOKIES.get("SSO")
    if not sso:
        return None

    jwt_payload = jwt.decode(sso, secret_key, algorithm=[algorithm])
    unique_user_value = jwt_payload.get(unique_user_field)
    user = get_user_model().objects.filter(**{unique_user_field: unique_user_value})
    if user and user.is_active:
        return (user, True)
    return None


def str_to_bool(val):
    if isinstance(val, str):
        val = 0 if val == "False" else 1
    return val
