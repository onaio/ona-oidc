# Ona OpenID Connect Client [![Build Status](https://travis-ci.org/onaio/ona-oidc.svg?branch=master)](https://travis-ci.org/onaio/ona-oidc)

A pluggable django application that implements OpenID Connect client functionalities.

## Installation

1. Install package using pip:

```sh
$ pip install -e git+https://github.com/onaio/ona-oidc.git#egg=ona-oidc
```

2. Add `oidc` to the list of `INSTALLED_APPS`

```python
...

INSTALLED_APPS = [
    ...,
    "oidc",
    ...,
]

...

```

3. Set `OPENID_CONNECT_VIEWSET_CONFIG` and `OPENID_CONNECT_AUTH_SERVERS` settings

```python
...
OPENID_CONNECT_VIEWSET_CONFIG = {
    "JWT_SECRET_KEY": JWT_SECRET_KEY,
    "JWT_ALGORITHM": JWT_ALGORITHM,
    "REQUIRED_USER_CREATION_FIELDS": ["email", "first_name", "username"],
    "USER_CREATION_FIELDS": ["email", "first_name", "last_name", "username"],
    "MAP_CLAIM_TO_MODEL": {
        "given_name": "first_name",
        "family_name": "last_name",
        "preferred_username": "username",
    },
    "SPLIT_NAME_CLAIM": False, # Whether to split the `name` claim into first_name & last_name if present
    "USER_UNIQUE_FILTER_FIELD": "username",
    "USE_SSO_COOKIE": True,
    "SSO_COOKIE_DATA": "email",
    "SSO_COOKIE_MAX_AGE": None,
    "SSO_COOKIE_DOMAIN": "localhost",
    "USE_AUTH_BACKEND": False,
    "AUTH_BACKEND": "",  # Defaults to django.contrib.auth.backends.ModelBackend
    "REDIRECT_AFTER_AUTH": "http://localhost:3000",
    "USE_RAPIDPRO_VIEWSET": False,
    "REPLACE_USERNAME_CHARACTERS": "-.",  # A string of characters to replace if found within the captured username when using the `USE_EMAIL_USERNAME` functionality
    "USERNAME_REPLACEMENT_CHARACTER": "_", # The character used to replace the characters within the `REPLACE_USERNAME_CHARACTERS` string
    # A map containing a field as a key and a map containing the regex and optional help_text strings as it's value
    # that's used to validate all field inputs retrieved for the particular key
    "FIELD_VALIDATION_REGEX": {
        "username": {
            "regex": "^(?!\d+$).{4,}$",
            "help_text": "Username should only contain alpha numeric characters",
        }
    },
    # A map containing an optional `default` key along side other regex keys i.e ^.*@ona.io$ with the value being
    # what defaults users with emails that match the regex or don't match any regex(default) should get.
    "USER_DEFAULTS": {
        "default": {
            "is_active": False
        },
        <regex_value>: {
            "is_active": True
        }
    }
}

OPENID_CONNECT_AUTH_SERVERS = {
    "microsoft": {
        "AUTHORIZATION_ENDPOINT": "https://login.microsoftonline.com/common/oauth2/v2.0/authorize",
        "CLIENT_ID": "client_id",
        "JWKS_ENDPOINT": "https://login.microsoftonline.com/common/discovery/v2.0/keys",
        "SCOPE": "openid profile",
        "TOKEN_ENDPOINT": "https://login.microsoftonline.com/common/oauth2/v2.0/token",
        "END_SESSION_ENDPOINT": "http://localhost:3000",
        "REDIRECT_URI": "http://localhost:8000/oidc/msft/callback",
        "RESPONSE_TYPE": "id_token",
        "RESPONSE_MODE": "form_post",
        "USE_NONCES": True,
        "NONCE_CACHE_TIMEOUT": 1800,
    }
}
...

```

4. (Optional) If you'd like to use the default OpenID Connect Viewset register the urls located in `oidc.urls`.

```python
# urls.py file

...
from django.conf.urls import include, url

urlpatterns = [
    ...,
    url(r"^", include("oidc.urls")),
    ...,
]
...

```
