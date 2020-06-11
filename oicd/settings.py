"""
Settings Module for the OICD App
"""

OPENID_CONNECT_VIEWSET_CONFIG = {
    "USER_CREATION_CLAIMS": ["email", "given_name", "family_name"],
    "MAP_CLAIM_TO_MODEL": {
        "email": "email",
        "given_name": "first_name",
        "family_name": "last_name",
    },
    "SSO_COOKIE_DATA": "email",
    "JWT_ALGORITHM": "HS256",
    "RENDERER_CLASSES": [
        "rest_framework.renderers.JSONRenderer",
        "rest_framework.renderers.TemplateHTMLRenderer",
    ],
}

OPENID_CONNECT_AUTH_SERVERS = {
    "default": {
        "SCOPE": "openid",
        "RESPONSE_TYPE": "id_token",
        "RESPONSE_MODE": "form_post",
        "USE_NONCES": True,
    }
}
