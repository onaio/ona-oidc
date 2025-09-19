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
    "USER_UNIQUE_FILTER_FIELDS": ["username", "email"],
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
            "regex": "^(?!\d+$)[a-zA-Z0-9]{3,}$",
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

## Import User (Optional)

The `ona-oidc` package includes an optional import user feature that allows administrators to search and import users from an external OIDC provider through the Django admin interface. This feature is useful for organizations that want to create users based on data from their identity provider.

### Configuration

To enable the import user feature, add the `OPENID_IMPORT_USER` setting to your Django settings:

```python
OPENID_IMPORT_USER = {
    "ENABLED": True,  # Set to False to disable the feature
    "TOKEN_ENDPOINT": "https://idp.example.com/oauth/token",  # OAuth2 token endpoint
    "SEARCH_ENDPOINT": "https://idp.example.com/users",  # User search API endpoint
    "CLIENT_ID": "your_client_id",  # OAuth2 client ID
    "CLIENT_SECRET": "your_client_secret",  # OAuth2 client secret
    "SCOPE": "users.read",  # OAuth2 scope for user search
    "QUERY_PARAM": "q",  # Query parameter name for search
    "MAP_CLAIM_TO_MODEL": {  # Maps identity provider claims to user model fields
        "email": "email",
        "given_name": "first_name",
        "family_name": "last_name",
        "preferred_username": "username",
    },
    "SEARCH_RESULTS_PATH": "data.results",  # Optional: JSON path to user list in response
}
```

### Usage

1. **Access the Feature**: Navigate to Django Admin → Authentication and Authorization → Users → Add user
2. **Search Users**: In the import form, start typing in the search box to find users from your identity provider
3. **Select User**: Click on a suggestion to populate the form fields with data from the identity provider
4. **Complete Import**: Fill in any additional required fields and save the user
