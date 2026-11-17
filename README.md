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
        "REQUEST_MODE": "form_post",
        "ISSUER": "https://login.microsoftonline.com/<tenant-id>/v2.0",
        "USE_NONCES": True,
        "NONCE_CACHE_TIMEOUT": 1800,
        "CHECK_EMAIL_VERIFIED": False,
        "REQUIRE_VERIFIED_EMAIL": False,
    }
}
...

```

`REQUEST_MODE` sets how the authorization code exchange sends the client
credentials to `TOKEN_ENDPOINT`. The default, `form_post`, sends them in the
request body. `query` puts them in the URL, where proxy and provider logs keep
them. Use it only for a provider that requires it. `manage.py check` warns
(`oidc.W003`) for each auth server in query mode. To keep query mode, add
`"oidc.W003"` to `SILENCED_SYSTEM_CHECKS`.

### Request timeouts

Every request to the provider gives up after `REQUESTS_TIMEOUT` seconds:
the JWKS fetch, the code exchange and the userinfo request. The default
is `(5, 30)`, which allows 5 seconds to connect and 30 to read. Set it per
auth server to a positive number or a `(connect, read)` pair. Any other
value, including `None`, raises `ImproperlyConfigured`. When a request
times out, the user gets the page that asks them to sign in again.

`OPENID_IMPORT_USER` takes the same `REQUESTS_TIMEOUT` key for the
admin's token and search requests.

### ID token validation

ID tokens must be signed with an algorithm in the per-server
`ID_TOKEN_ALLOWED_ALGORITHMS` list and carry `exp`, `iat`, `aud` and `sub`
claims; tokens that do not are rejected. The list defaults to the
RSA family (`RS256`/`RS384`/`RS512`/`PS256`/`PS384`/`PS512`) and may
only contain algorithms from that family — set it to a subset, e.g.
`["RS256"]`, to accept exactly what your provider signs with. Any
other value raises `ImproperlyConfigured`. A token with more than one
distinct audience must also carry an `azp` claim equal to `CLIENT_ID`.
The `sub` and `azp` checks are on by default, and each can be turned
off per server. Set `ID_TOKEN_REQUIRE_SUB` to `False` for a provider
that omits `sub`. Set `ID_TOKEN_VERIFY_AZP` to `False` only for a
provider that sends several audiences without `azp`. Turning it off
also accepts a token whose `azp` names another client. When
`ISSUER` is set, the token's `iss` claim must match it exactly; use the
`issuer` value from the provider's
`/.well-known/openid-configuration` document. For Microsoft
Entra ID that value contains your tenant id — tokens never carry the
literal `common`, so a multi-tenant app on the `common` endpoint
cannot use a single exact-match `ISSUER` and should leave it unset.
When `ISSUER` is not set, the `iss` claim is not checked and every
verification logs a warning; a future release will require the
setting.

### Verified email addresses

The callback signs a user in to the existing account whose email matches
the `email` claim or, without one, any entry of the `emails` claim. A
provider that lets people register can issue a token for an address they
never proved they own. Set `CHECK_EMAIL_VERIFIED` to `True` on an auth
server to refuse such logins. The callback then refuses a login whose
claims carry an address and an `email_verified` claim that is not `true`
or the string `"true"`. The string may have any case and surrounding
spaces. A refused login neither links nor creates an account. The
setting is off by default. Every auth server signs in to the same
accounts, so turn the check on for each server whose users can register
their own addresses.

Blank addresses never match an account, whatever the settings. The
callback ignores an `email` claim or `emails` entry that is empty, only
spaces, or not a string, and an SSO cookie with a blank value signs in
to no account. Claims left with no address are handled like claims that
never had one. The callback falls back to the userinfo endpoint, which
needs an access token, so with the default `id_token` response type the
login is refused. An account created without an address gets only the
`default` entry of `USER_DEFAULTS`.

Some providers, such as Microsoft Entra ID, omit the claim. With the
check on, their addresses are trusted. Set `REQUIRE_VERIFIED_EMAIL` to
`True` to also refuse logins that carry an address but no
`email_verified` claim. `REQUIRE_VERIFIED_EMAIL` turns the check on by
itself.

Some providers send `false` for users an admin created or imported
without verifying their address, as Keycloak does. With the check on,
those users get a 401 page until the address is verified at the
provider.

The check trusts one `email_verified` claim for every address the
callback matches. Don't rely on it if your provider lists unverified
addresses in `emails`, or if `MAP_CLAIM_TO_MODEL` maps another claim
onto `email`.

### The username form

When a new user needs to choose a username, the callback renders
`oidc/oidc_user_data_entry.html`. The callback keeps the verified token,
its claims and the login's `state` in the Django cache. The form carries
only a single-use `login_continuation` key that points at them. The JSON
rendering of that response carries the same key.

- Every process that serves the callback must share one cache. Django's
  default `LocMemCache` is per process, so a re-submit that reaches
  another worker is refused. This applies even with `USE_NONCES=False`.
- The cache's `delete` must report whether it removed the key. Do not
  set `default_noreply=True` on a memcached backend.
- A template override must post `login_continuation` back, not
  `id_token`:

  ```html
  <input type="hidden" name="login_continuation" value="{{ login_continuation }}">
  ```

  A form that posts no continuation is refused, and the callback logs a
  warning.
- The form lasts `NONCE_CACHE_TIMEOUT` seconds at most, and never longer
  than the ID token would still verify. `NONCE_CACHE_TIMEOUT` must be
  positive. With `USE_PKCE`, the re-submit
  also needs the PKCE verifier, which expires `PKCE_CODE_CHALLENGE_TIMEOUT`
  seconds after the login started.
### Browser binding (login CSRF)

Every login carries a `state` value, and the login redirect sets a
short-lived, signed, `HttpOnly` cookie bound to that one login
attempt. The callback only honours an authorization response whose
echoed `state` matches the cookie set when its login started, so an
attacker cannot replay a response captured in one browser into
another to log a victim into the attacker's account (RFC 9700 §4.4).
Each attempt has its own cookie, so logins started in other tabs or
against other configured providers stay independently completable;
a cookie lapses 30 minutes after its login starts.

- **`ENFORCE_BROWSER_BINDING`** (`bool`, default `True`), per auth
  server. Set it to `False` only for deployments whose logins do not
  start at this application's login endpoint, such as IdP-initiated
  logins from the provider's own portal. Those logins can never carry
  the cookie, so the callback would always reject them.
- With `RESPONSE_MODE=form_post` the IdP delivers the response as a
  cross-site POST, so the cookie carries `SameSite=None; Secure` and
  the deployment must run over HTTPS. `query` mode uses
  `SameSite=Lax`, with `Secure` set when Django sees the request as
  HTTPS — a deployment that terminates TLS at a proxy needs Django's
  `SECURE_PROXY_SSL_HEADER` configured (and the proxy sending the
  matching header) for that.
- Logins in flight when this feature is first deployed predate the
  cookie, so the callback rejects them; retrying the login recovers.

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

The cookie's JWT carries `iat` and `exp` claims: the token expires
`SSO_COOKIE_MAX_AGE` seconds after it is minted, or after 7 days when
`SSO_COOKIE_MAX_AGE` is not set. Tokens minted by older releases have
no `exp` and are rejected; their holders are sent through the OIDC
login flow once more after upgrading.

`JWT_SECRET_KEY` is required for the SSO features: minting the cookie and
verifying it with `authenticate_sso` both raise `ImproperlyConfigured`
when it is missing or empty. Invalid tokens (bad signature, malformed
value, expired) are an authentication miss — `authenticate_sso` returns
`None` rather than raising.

Future work: once `Secure=True` is enforced cohort-wide, the cookie name
can migrate to `__Secure-SSO` for browser-enforced guarantees.

### Credentials in error reports

The token exchange, `authenticate_sso`, the viewsets' token-handling methods
and the admin user search hide their local variables, and those of every
function they call, from Django error reports. The viewsets also mask every POSTed value. A subclass that
sets its own `renderer_classes` should render HTML with
`oidc.renderers.SensitiveTemplateHTMLRenderer`. Django renders the username
form after the view returns, and a plain `TemplateHTMLRenderer` lets an error
report show the sign-in data the form carries. Sentry reads frame locals
itself and ignores these markers, so hosts that use Sentry need their own
scrubbing.

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
    "REQUESTS_TIMEOUT": (5, 30),  # Optional: (connect, read) seconds for each request
}
```

### Usage

1. **Access the Feature**: Navigate to Django Admin → Authentication and Authorization → Users → Add user
2. **Search Users**: In the import form, start typing in the search box to find users from your identity provider
3. **Select User**: Click on a suggestion to populate the form fields with data from the identity provider
4. **Complete Import**: Fill in any additional required fields and save the user

## Upgrading

### Users created by 2.10.0 and earlier have a usable empty password

ona-oidc 2.10.0 and earlier created SSO users with an empty password. Django treats an empty password as usable, so those users can set a local password through the password reset flow. Later releases give new SSO users an unusable password. Existing users keep the empty one.

To remove it, run this once in your project, for example in a data migration:

```python
from django.contrib.auth import get_user_model

for user in get_user_model().objects.filter(password="").iterator():
    user.set_unusable_password()
    user.save(update_fields=["password"])
```

ona-oidc does not record which users it created, so this changes every user with an empty password. Check first that your project doesn't create users without a password and then rely on the reset email to let them set one, as an invitation flow might. Those users would stop receiving reset emails.
