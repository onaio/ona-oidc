# Ona OpenID Connect Client [![CI](https://github.com/onaio/ona-oidc/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/onaio/ona-oidc/actions/workflows/ci.yml)

A pluggable django application that implements OpenID Connect client functionalities.

## Installation

1. Install package using pip:

```sh
pip install -e git+https://github.com/onaio/ona-oidc.git#egg=ona-oidc
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
    "SSO_COOKIE_PATH": "/",
    "SSO_COOKIE_SECURE": None,  # None => fall back to settings.SESSION_COOKIE_SECURE
    "SSO_COOKIE_SAMESITE": "Lax",  # "Strict" | "Lax" | "None"
    "SSO_COOKIE_HTTPONLY": True,
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

### SSO cookie security

The `SSO` cookie emitted on successful authentication honours these keys:

- **`SSO_COOKIE_SECURE`** (`bool | None`, default `None`). When `None`, the
  Secure flag falls back to `settings.SESSION_COOKIE_SECURE`. Set this to
  `True` to force Secure on regardless of the Django session setting, or
  `False` to force it off. Production deployments should either set
  `SESSION_COOKIE_SECURE=True` (recommended — applies across session/CSRF/SSO
  cookies) or set `SSO_COOKIE_SECURE=True` explicitly.
- **`SSO_COOKIE_SAMESITE`** (`str`, default `"Lax"`). One of `"Strict"`,
  `"Lax"`, or `"None"`. `"Lax"` is the right default for the standard
  redirect-callback flow. Federated or iframe-embedded OIDC deployments must
  use `"None"` + `Secure=True` — the viewset refuses to start with
  `SameSite="None"` while Secure is falsy (Django/browsers reject such
  cookies anyway).
- **`SSO_COOKIE_HTTPONLY`** (`bool`, default `True`). Leave on unless you
  have a specific reason to expose the cookie to JavaScript.
- **`SSO_COOKIE_PATH`** (`str`, default `"/"`).

Future work: once `Secure=True` is enforced cohort-wide, the cookie name
can migrate to `__Secure-SSO` for browser-enforced guarantees.

### Forwarding query parameters to the authorization endpoint

The login viewset forwards browser query parameters to the configured
authorization endpoint only if they appear in a deployment-defined
allowlist on the relevant auth server. The default is an empty list,
so no browser query parameters reach the IdP unless explicitly
opted in.

```python
OPENID_CONNECT_AUTH_SERVERS = {
    "microsoft": {
        ...,
        "LOGIN_QUERY_PARAM_ALLOWLIST": [
            "prompt",
            "ui_locales",
            "acr_values",
            "login_hint",
        ],
    }
}
```

`next` is consumed by ona-oidc for redirect-after-auth caching and is
never forwarded, regardless of allowlist. The client-side
`RESERVED_AUTHORIZE_PARAMS` filter (covering OIDC params ona-oidc
generates plus JAR / SIOP request-object hooks) applies as a second
boundary for any programmatic caller of `OpenIDClient.login()`.

Two encoding details worth knowing:

- If a caller repeats a key (e.g. `?prompt=login&prompt=consent`),
  only the last value is forwarded. Most IdPs would resolve the
  duplicate the same way, but if you need to send multiple values for
  one key, encode them into a single value at the caller.
- Whitespace and other reserved characters in forwarded values are
  percent-encoded (e.g. spaces → `%20`, not `+`). Both forms are
  spec-equivalent in URL query strings; ona-oidc picks `%20` for
  log readability.

### Validating the post-authentication redirect target (`next`)

The viewset only accepts a `next` query parameter that points at a
relative path or a host explicitly trusted in
`OPENID_CONNECT_AUTH_SERVERS[<server>]["LOGIN_REDIRECT_ALLOWED_HOSTS"]`.
The current request's own host is always trusted, so same-origin
deployments need no extra config. Unsafe values are dropped (logged at
WARNING) and the post-auth redirect falls back to the configured
`OPENID_CONNECT_VIEWSET_CONFIG["REDIRECT_AFTER_AUTH"]`.

```python
OPENID_CONNECT_AUTH_SERVERS = {
    "microsoft": {
        ...,
        "LOGIN_REDIRECT_ALLOWED_HOSTS": ["spa.example.com"],
    }
}
```

Validation runs Django's `url_has_allowed_host_and_scheme`, so
`javascript:` / `data:` schemes and protocol-relative `//evil` URLs
are rejected. Under HTTPS, `http://` redirects are also rejected.

`next` is honored regardless of `USE_NONCES`. When the caller supplies
`next`, ona-oidc allocates a nonce and caches the validated redirect
target under it for the duration of the auth round-trip; the callback
restores the value from cache and uses it as the post-auth redirect.
With `USE_NONCES=False` the nonce is still emitted purely as the cache
key — no IdP-side nonce verification is performed.

### Keycloak Account REST proxy (`ACCOUNT_ENDPOINT`)

The account-proxy actions (sessions, linked accounts, credentials) forward
to Keycloak's Account REST API, and are read-and-revoke only — there is no
profile-update endpoint. Being Keycloak-specific, they live in
`KeycloakAccountMixin` rather than in the base viewset, and a deployment
opts in by routing to a viewset that mixes them in:

```python
# Ready-made: the default viewset plus the proxy.
OPENID_CONNECT_VIEWSET_CONFIG = {
    "VIEWSET_CLASS": "oidc.keycloak.KeycloakOpenIDConnectViewset",
}
```

```python
# Or compose it with your own subclass.
from oidc.keycloak import KeycloakAccountMixin
from oidc.viewsets import UserModelOpenIDConnectViewset


class MyOpenIDConnectViewset(KeycloakAccountMixin, UserModelOpenIDConnectViewset):
    ...
```

Without the mixin these routes are not generated at all. Then point
`ACCOUNT_ENDPOINT` at that realm's account root:

```python
OPENID_CONNECT_AUTH_SERVERS = {
    "keycloak": {
        ...,
        "ACCOUNT_ENDPOINT": "https://idp.example.com/realms/example/account",
    }
}
```

The setting is optional; with the mixin in place but `ACCOUNT_ENDPOINT`
unset, the proxy actions return `503`. Calls are made with the signed-in user's own `access_token`, so
they need the `manage-account` role — granted to every realm user by
default.

The proxy also requires a **token-producing flow**: the access/refresh
pair it spends is only ever obtained by the authorization-code exchange
at callback time. That means, for the auth server used with the proxy:

* `RESPONSE_TYPE: "code"` — the repository default is `"id_token"`
  (implicit flow), which returns an id_token only. With it, login works
  but nothing is stashed, and every proxy action answers `401` even
  though `ACCOUNT_ENDPOINT` is set — a symptom worth recognising.
* `TOKEN_ENDPOINT` set — used for the code exchange and again for the
  refresh-on-401 retry. Unset, it breaks the callback itself: the exchange
  posts to `None` and the login ends on the `401` error page, so you never
  reach the proxy. The `503` case is the refresh path only.

A hybrid `RESPONSE_TYPE` such as `"code id_token"` does not work either —
the callback short-circuits the code exchange whenever an `id_token` is
already present, so no access token is ever obtained.

These routes take identity from the OIDC tokens in `request.session`
rather than `request.user`, and so run with DRF authentication
disabled. All methods are instead gated by `IsCsrfSafeAccountRequest`:
every request's `Origin` must be absent (same-origin) or in the same
trusted-host set as `LOGIN_REDIRECT_ALLOWED_HOSTS` — this is what keeps
the listings unreadable even from a deployment whose CORS reflects
arbitrary origins — and state-changing methods must additionally carry a
custom header. Neither check depends on the session cookie's `SameSite`
attribute or on the deployment's CORS configuration.

The header defaults to `X-Ona-Account-Request` and is configurable:

```python
OPENID_CONNECT_VIEWSET_CONFIG = {
    ...,
    "ACCOUNT_REQUEST_HEADER": "X-Acme-Account-Request",
}
```

Any name works as a CSRF defence — what matters is that cross-site
markup cannot set a custom header at all, not which name is used. The
SPA must send whichever name is configured.

#### Session tokens are scoped per auth server

`OPENID_CONNECT_AUTH_SERVERS` is a keyed dict and every key gets its own
routes, so the URL selects the provider while the Django session holds the
tokens. They are therefore stored under provider-scoped session keys —
`oidc_access_token:<auth_server>`, `oidc_refresh_token:<auth_server>` and
`oidc_id_token:<auth_server>` — rather than one global name.

This matters only in multi-provider deployments, where a single global key
would be readable from *every* provider's route: a request to provider B
would spend provider A's access token against B's account endpoint and,
because B answers a foreign token with `401` (which the retry path reads as
"expired"), go on to POST A's long-lived refresh token to B's token
endpoint. Logout would likewise replay A's `id_token` to B as
`id_token_hint`. Scoping makes those unrepresentable rather than merely
checked.

There is deliberately no fallback read of the old un-scoped keys — that
would reinstate the cross-provider path. Sessions established before this
change get one `401` and sign in again, the same fallback sessions
predating the token stash already hit.

`logout` clears all three of this provider's keys before redirecting to
the end-session endpoint. That redirect may never be completed — closed
tab, declined confirm screen, unreachable IdP — so it is the only point
in the flow the server controls; leaving the pair behind would let a
logged-out session keep calling the account proxy as the user. Other
providers' tokens are untouched, since logout is per-provider.

The tokens are also only written once the login is *accepted*. The IdP
vouching for a user is not the platform accepting them — the callback can
still refuse (`AUTO_CREATE_USER` off, required claims missing, validation
failures) — so nothing touches the session until the success exit. A
refused caller's session therefore gets a `401` from the proxy, and no
credential is left at rest for a caller who, never having signed in, will
never log out to clear it.

One flow needs more than that: when the claims carry no usable username
the callback answers with an entry form, and the browser re-POSTs only
the `id_token` — so the access/refresh pair obtained by the first request
is parked in `<name>:<auth_server>:pending` until the resubmit. Those
slots are written on that path alone. The parked pair is tagged with the
`id_token` it belongs to and handed back only on a match, because one
session can be running two logins at once (two tabs): pairing one login's
`id_token` with another's tokens would sign the browser in as one
identity while the proxy acted on the other's Keycloak account. A
mismatch is dropped, so login completes and the proxy answers `401` until
the next full sign-in.

Because that session now carries a refresh token, two Django-level
choices stop being neutral:

* **A server-side `SESSION_ENGINE` is required.** Signed-cookie sessions
  are signed but not encrypted — the contents are client-readable and stay
  replayable after logout, since there is no server-side record to delete.
  Pairing that backend with a proxy-enabled viewset is a deploy check
  (`oidc.E001`), so `manage.py check` fails rather than the first user who
  tries to sign in; the viewset also refuses at request time as a backstop.
  Viewsets that keep only the id_token (which the browser already holds)
  are unaffected.
* **The session id is rotated when the tokens are written.** Django's
  `login()` would do this, but only runs under `USE_AUTH_BACKEND`, so the
  proxy calls `cycle_key()` itself — otherwise a planted session id would
  end up holding the victim's tokens.

Outbound calls to the IdP carry a `(connect, read)` timeout, default
`(5, 15)`, configurable per auth server:

```python
OPENID_CONNECT_AUTH_SERVERS = {
    "keycloak": {
        ...,
        "REQUEST_TIMEOUT": (5, 15),
    }
}
```

`logout` also removes the pre-namespacing `oidc_id_token` /
`oidc_access_token` / `oidc_refresh_token` keys. That is a write-side
sweep only — it does not reinstate the fallback *read*, so it cannot
bring back the cross-provider path. Without it, a token stashed before
the rename would outlive every sign-out, since the session is flushed
only under `USE_AUTH_BACKEND`.

#### Deployment requirements for the origin checks

The trusted-host set is `LOGIN_REDIRECT_ALLOWED_HOSTS` plus the request's
own host, so both the `next` validation and the account-proxy `Origin`
check inherit their strength from Django's `ALLOWED_HOSTS`:

* **Scope `ALLOWED_HOSTS` to the hosts you serve.** The request host is
  read via `request.get_host()`, which Django rejects with a `400`
  unless it matches `ALLOWED_HOSTS`. That validation is what keeps an
  attacker-supplied `Host` out of the trusted set. With
  `ALLOWED_HOSTS = ["*"]` there is no validation left, the header is
  echoed back verbatim, and both checks degrade to comparing one
  request header against another.

* **With `USE_X_FORWARDED_HOST = True`, the proxy must strip any
  client-supplied `X-Forwarded-Host`.** Django prefers that header over
  `Host`, and unlike `Host` a page can set it on a `fetch`. A proxy that
  forwards it lets a caller nominate its own origin as trusted.

### Routing to your own viewset (`VIEWSET_CLASS`)

Deployments that subclass the viewset — to reject certain account types,
adjust cookie handling, and so on — can keep using `include("oidc.urls")`
by naming the subclass:

```python
OPENID_CONNECT_VIEWSET_CONFIG = {
    ...,
    "VIEWSET_CLASS": "myapp.oidc_viewsets.MyOpenIDConnectViewset",
}
```

Every route then goes to that class, including the account-proxy routes
and their CSRF configuration. Without this the only way to change the
viewset is to copy `oidc/urls.py` into your project, which means
mirroring every future route and every `as_view()` kwarg by hand.

An unimportable path raises rather than falling back to the built-in
viewset — a silent fallback would drop whatever access rules the
subclass enforces.

`USE_RAPIDPRO_VIEWSET` is the older boolean form and still works;
`VIEWSET_CLASS` takes precedence when both are set.

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
