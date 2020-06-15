# ona-oicd [![Build Status](https://travis-ci.org/onaio/ona-oicd.svg?branch=master)](https://travis-ci.org/onaio/ona-oicd)

A pluggable django application that implements OpenID Connect client functionalities.

## Installation

1. Install package using pip:

```sh
$ pip install -e git+https://github.com/onaio/ona-oicd.git#egg=ona-oicd
```

2. Add `oicd` to the list of `INSTALLED_APPS`

```python
...

INSTALLED_APPS = [
    ...,
    "oicd",
    ...,
]

...

```

3. Set `OPENID_CONNECT_VIEWSET_CONFIG` and `OPENID_CONNECT_AUTH_SERVERS` settings

```python
...
OPENID_CONNECT_VIEWSET_CONFIG = {
    "REDIRECT_AFTER_AUTH": "http://localhost:3000",
    "USE_SSO_COOKIE": True,
    "SSO_COOKIE_DATA": "email",
    "JWT_SECRET_KEY": JWT_SECRET_KEY,
    "JWT_ALGORITHM": JWT_ALGORITHM,
    "SSO_COOKIE_MAX_AGE": None,
    "SSO_COOKIE_DOMAIN": "localhost",
    "USE_AUTH_BACKEND": False,
    "AUTH_BACKEND": "",  # Defaults to django.contrib.auth.backends.ModelBackend
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
        "USE_NONCES": True
    }
}
...

```

4. (Optional) If you'd like to use the default OpenID Connect Viewset register the urls located in `oicd.urls`.

```python
# urls.py file

...
from oicd.urls import urlpatterns as oicd_urls

urlpatterns = [
    ...
]
urlpatterns += oicd_urls
...

```
