"""
Settings Module for the OICD App
"""

OPENID_CONNECT_VIEWSET_CONFIG = {
    "USER_CREATION_CLAIMS": ["email", "given_name", "family_name"],
    "MAP_CLAIM_TO_MODEL": {
        "email": "email",
        "given_name": "first_name",
        "family_name": "last_name"
    },
    "REDIRECT_AFTER_AUTH": "http://localhost:3000",
    "USE_SSO_COOKIE": False,
    "SSO_COOKIE_DATA": "email",
    "JWT_SECRET_KEY": "JSON Web Token",
    "JWT_ALGORITHM": "HS256",
    "SSO_COOKIE_MAX_AGE": None,
    "SSO_COOKIE_DOMAIN": "",
    "PERMISSION_CLASSES": [],
    "AUTHENTICATION_CLASSES": []
}

OPENID_CONNECT_AUTH_SERVERS = {
    "microsoft": {
        "AUTHORIZATION_ENDPOINT": "https://login.microsoftonline.com/common/oauth2/v2.0/authorize",
        "CLIENT_ID": "",
        "JWKS_ENDPOINT": "https://login.microsoftonline.com/common/discovery/v2.0/keys",
        "SCOPE": "openid profile",
        "TOKEN_ENDPOINT": "https://login.microsoftonline.com/common/oauth2/v2.0/token",
        "END_SESSION_ENDPOINT": "http://localhost:3000",
        "REDIRECT_URI": "http://localhost:8000/oidc/microsoft/callback",
        "RESPONSE_TYPE": "id_token",
        "RESPONSE_MODE": "form_post",
        "USE_NONCES": True
    }
}
