"""
Settings Module for the oidc App
"""

OPENID_CONNECT_VIEWSET_CONFIG = {
    "REQUIRED_USER_CREATION_FIELDS": ["email", "first_name", "username"],
    "USER_CREATION_FIELDS": ["email", "first_name", "last_name", "username"],
    "USER_DEFAULTS": {},
    "MAP_CLAIM_TO_MODEL": {
        "given_name": "first_name",
        "family_name": "last_name",
        "preferred_username": "username",
    },
    "SPLIT_NAME_CLAIM": False,
    "USE_EMAIL_USERNAME": False,
    "USER_UNIQUE_FILTER_FIELD": "username",
    "SSO_COOKIE_DATA": "email",
    "JWT_ALGORITHM": "HS256",
    "FIELD_VALIDATION_REGEX": {
        "username": {
            "regex": "^(?!\d+$).{4,}$",  # noqa
            "help_text": "Username should only contain alpha numeric characters",
        }
    },
    "REPLACE_USERNAME_CHARACTERS": "-.",
    "USERNAME_REPLACEMENT_CHARACTER": "_",
}

OPENID_CONNECT_AUTH_SERVERS = {
    "default": {
        "SCOPE": "openid",
        "RESPONSE_TYPE": "id_token",
        "RESPONSE_MODE": "form_post",
        "USE_NONCES": True,
        "NONCE_CACHE_TIMEOUT": 1800,
    }
}
