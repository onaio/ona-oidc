import jwt

from django.contrib.auth import get_user_model


def authenticate_sso(
        request, secret_key: str, algorithm: str, unique_user_field: str = 'email'):
    sso = request.META.get('HTTP_SSO') or request.COOKIES.get('SSO')
    if not sso:
        return None

    jwt_payload = jwt.decode(
        sso, secret_key, algorithm=[algorithm])
    unique_user_value = jwt_payload.get(unique_user_field)
    user = get_user_model().objects.filter(
        **{unique_user_field: unique_user_value})
    if user and user.is_active:
        return (user, True)
    return None
