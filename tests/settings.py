"""
Test Settings
"""
import os

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

INSTALLED_APPS = (
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.gis",
    "rest_framework",
    "oidc",
)

DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.sqlite3",
        "NAME": str(BASE_DIR + "/db.sqlite3"),
    }
}

OPENID_CONNECT_VIEWSET_CONFIG = {
    "REDIRECT_AFTER_AUTH": "http://localhost:3000",
    "USE_SSO_COOKIE": True,
    "SSO_COOKIE_DATA": "email",
    "JWT_SECRET_KEY": "secret",
    "JWT_ALGORITHM": "HS256",
    "SSO_COOKIE_MAX_AGE": None,
    "SSO_COOKIE_DOMAIN": "localhost",
}

OPENID_CONNECT_AUTH_SERVERS = {
    "default": {
        "AUTHORIZATION_ENDPOINT": "example.com/oauth2/v2.0/authorize",
        "CLIENT_ID": "client",
        "JWKS_ENDPOINT": "example.com/discovery/v2.0/keys",
        "SCOPE": "openid profile",
        "TOKEN_ENDPOINT": "example.com/oauth2/v2.0/token",
        "END_SESSION_ENDPOINT": "http://localhost:3000",
        "REDIRECT_URI": "http://localhost:8000/oidc/msft/callback",
        "RESPONSE_TYPE": "id_token",
        "RESPONSE_MODE": "form_post",
        "USE_NONCES": False,
    }
}

ROOT_URLCONF = "oidc.urls"
SECRET_KEY = "secret"
