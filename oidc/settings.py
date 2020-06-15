"""
Settings Module for the oidc App
"""

OPENID_CONNECT_VIEWSET_CONFIG = {
    "USER_CREATION_CLAIMS": ["email", "given_name", "family_name", "username"],
    "MAP_CLAIM_TO_MODEL": {
        "email": "email",
        "given_name": "first_name",
        "family_name": "last_name",
        "username": "username",
    },
    "SSO_COOKIE_DATA": "email",
    "JWT_ALGORITHM": "HS256",
}

OPENID_CONNECT_AUTH_SERVERS = {
    "default": {
        "SCOPE": "openid",
        "RESPONSE_TYPE": "id_token",
        "RESPONSE_MODE": "form_post",
        "USE_NONCES": True,
    }
}
