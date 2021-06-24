"""
Settings Module for the oidc App
"""

OPENID_CONNECT_VIEWSET_CONFIG = {
    "REQUIRED_USER_CREATION_FIELDS": ["email", "first_name", "username"],
    "USER_CREATION_FIELDS": ["email", "first_name", "last_name", "username"],
    "MAP_CLAIM_TO_MODEL": {
        "given_name": "first_name",
        "family_name": "last_name",
        "preferred_username": "username",
    },
    "SPLIT_NAME_CLAIM": False,
    "USER_UNIQUE_FILTER_FIELD": "username",
    "SSO_COOKIE_DATA": "email",
    "JWT_ALGORITHM": "HS256",
    "FIELD_VALIDATION_REGEX": {
        "username": "(?!^\d+$)^.+$"
    }
}

OPENID_CONNECT_AUTH_SERVERS = {
    "default": {
        "SCOPE": "openid",
        "RESPONSE_TYPE": "id_token",
        "RESPONSE_MODE": "form_post",
        "USE_NONCES": True,
    }
}
