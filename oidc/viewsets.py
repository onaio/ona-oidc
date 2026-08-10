"""
oidc Viewsets module
"""

import importlib
import logging
import re
import traceback
from typing import List, Optional, Tuple

from django.conf import settings
from django.contrib.auth import get_user_model, login
from django.contrib.auth import logout as logout_backend
from django.core.cache import cache
from django.core.exceptions import ImproperlyConfigured
from django.db.models import Q
from django.http import (
    HttpRequest,
    HttpResponse,
    HttpResponseBadRequest,
    HttpResponseRedirect,
)
from django.utils import timezone
from django.utils.translation import gettext as _

import jwt
from jwt.exceptions import PyJWTError
from rest_framework import permissions, status, viewsets
from rest_framework.decorators import action
from rest_framework.renderers import JSONRenderer, TemplateHTMLRenderer
from rest_framework.response import Response
from rest_framework.reverse import reverse

import oidc.settings as default
from oidc.client import (
    REDIRECT_AFTER_AUTH,
    NoJSONWebKeyFound,
    NonceVerificationFailed,
    OpenIDClient,
    TokenVerificationFailed,
    state_cache_key,
)
from oidc.utils import (
    ACCESS_TOKEN_SESSION_KEY,
    ID_TOKEN_SESSION_KEY,
    REFRESH_TOKEN_SESSION_KEY,
    TOKEN_SESSION_BASE_KEYS,
    authenticate_sso,
    email_usename_to_url_safe,
    get_login_query_param_allowlist,
    get_logout_query_param_allowlist,
    get_viewset_config,
    is_safe_login_redirect,
    pending_token_session_key,
    replace_characters_in_username,
    stash_pending_tokens,
    str_to_bool,
    take_pending_tokens,
    token_session_key,
)

default_config = getattr(default, "OPENID_CONNECT_VIEWSET_CONFIG", {})
SSO_COOKIE_NAME = "SSO"

# Hidden field on oidc_user_data_entry.html that signals the form is
# re-POSTing to the callback URL. Not a security boundary — the value
# is a public constant and can be forged. Its purpose is to make the
# "use id_token from body, skip auth-code exchange" path deliberate
# (only triggered by our own form), so the broader code-exchange path
# remains the default. Real protection comes from
# verify_and_decode_id_token (signature, expiry, nonce).
USERNAME_FORM_MARKER_FIELD = "from_username_form"
USERNAME_FORM_MARKER_VALUE = "1"

# Rendering this template is the one callback exit allowed to leave a token
# pair parked in the session; see ``callback``.
USERNAME_FORM_TEMPLATE = "oidc/oidc_user_data_entry.html"

# Defaults used when FIELD_VALIDATION_REGEX has no "username" entry.
# Kept conservative so the rendered form matches the legacy template
# behaviour for deployments that haven't customized validation.
DEFAULT_USERNAME_PATTERN = r"^[A-Za-z0-9_]*$"
DEFAULT_USERNAME_HELP_TEXT = "Username should not contain . @ - symbols"

logger = logging.getLogger(__name__)


class BaseOpenIDConnectViewset(viewsets.ViewSet):
    """
    BaseOpenIDConnectViewset: Base viewset that implements login and logout
    Open ID Connect Functionality.
    """

    permission_classes = [permissions.AllowAny]
    renderer_classes = [JSONRenderer, TemplateHTMLRenderer]
    user_model = None

    #: Whether ``callback`` keeps the access/refresh pair in the session.
    #: Off by default: only a subclass that later calls the IdP on the
    #: user's behalf needs them, and a stashed refresh token is long-lived
    #: credential material at rest in the session store. Subclasses that
    #: need it turn it on -- see ``oidc.keycloak.KeycloakAccountMixin``.
    stash_oidc_tokens = False

    def perform_authentication(self, request):
        if getattr(self, "action", None) == "session":
            return
        return super().perform_authentication(request)

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        config = get_viewset_config()
        self.jwt = config.get("JWT_SECRET_KEY", "")
        self.required_fields = config.get(
            "REQUIRED_USER_CREATION_FIELDS",
            default_config["REQUIRED_USER_CREATION_FIELDS"],
        )
        self.user_creation_fields = config.get(
            "USER_CREATION_FIELDS", default_config["USER_CREATION_FIELDS"]
        )
        self.user_default_fields = config.get("USER_DEFAULTS", {})
        self.map_claim_to_model = config.get(
            "MAP_CLAIM_TO_MODEL", default_config["MAP_CLAIM_TO_MODEL"]
        )
        self.use_sso = str_to_bool(config.get("USE_SSO_COOKIE", True))
        self.sso_cookie = config.get(
            "SSO_COOKIE_DATA", default_config["SSO_COOKIE_DATA"]
        )
        self.jwt_algorithm = config.get(
            "JWT_ALGORITHM", default_config["JWT_ALGORITHM"]
        )
        self.split_name_claim = config.get(
            "SPLIT_NAME_CLAIM", default_config["SPLIT_NAME_CLAIM"]
        )
        self.use_email_as_username = config.get(
            "USE_EMAIL_USERNAME", default_config["USE_EMAIL_USERNAME"]
        )
        self.cookie_max_age = config.get("SSO_COOKIE_MAX_AGE")
        self.cookie_domain = config.get("SSO_COOKIE_DOMAIN", "localhost")
        self.cookie_secure = config.get(
            "SSO_COOKIE_SECURE",
            default_config.get("SSO_COOKIE_SECURE"),
        )
        self.cookie_samesite = config.get(
            "SSO_COOKIE_SAMESITE",
            default_config.get("SSO_COOKIE_SAMESITE", "Lax"),
        )
        self.cookie_httponly = str_to_bool(
            config.get(
                "SSO_COOKIE_HTTPONLY",
                default_config.get("SSO_COOKIE_HTTPONLY", True),
            )
        )
        self.cookie_path = config.get(
            "SSO_COOKIE_PATH",
            default_config.get("SSO_COOKIE_PATH", "/"),
        )
        if self.cookie_samesite == "None" and not self._resolve_cookie_secure():
            raise ImproperlyConfigured(
                "SSO_COOKIE_SAMESITE='None' requires Secure=True; "
                "set SSO_COOKIE_SECURE=True or SESSION_COOKIE_SECURE=True."
            )
        if self.stash_oidc_tokens and (
            getattr(settings, "SESSION_ENGINE", "")
            == "django.contrib.sessions.backends.signed_cookies"
        ):
            # Signed but not encrypted: client-readable, and replayable
            # after logout since there is no server-side record to delete.
            raise ImproperlyConfigured(
                "The Keycloak account proxy stores access and refresh tokens "
                "in request.session, which the signed_cookies backend would "
                "expose to the client and leave replayable after logout. Use "
                "a server-side SESSION_ENGINE (db, cache, cached_db, file)."
            )
        self.use_auth_backend = str_to_bool(config.get("USE_AUTH_BACKEND", False))
        self.auth_backend = config.get(
            "AUTH_BACKEND", "django.contrib.auth.backends.ModelBackend"
        )
        self.unique_user_filter_fields = config.get(
            "USER_UNIQUE_FILTER_FIELDS", default_config["USER_UNIQUE_FILTER_FIELDS"]
        )
        self.replaceable_username_characters = config.get(
            "REPLACE_USERNAME_CHARACTERS", default_config["REPLACE_USERNAME_CHARACTERS"]
        )
        self.username_char_replacement = config.get(
            "USERNAME_REPLACEMENT_CHARACTER",
            default_config["USERNAME_REPLACEMENT_CHARACTER"],
        )
        self.field_validation_regex = config.get(
            "FIELD_VALIDATION_REGEX", default_config["FIELD_VALIDATION_REGEX"]
        )
        self.auto_create_user = str_to_bool(
            config.get("AUTO_CREATE_USER", default_config["AUTO_CREATE_USER"])
        )

    def _get_client(self, auth_server: str) -> Optional[OpenIDClient]:
        auth_config = getattr(settings, "OPENID_CONNECT_AUTH_SERVERS", {})

        if auth_server in auth_config:
            return OpenIDClient(auth_server)
        return None

    def _resolve_cookie_secure(self) -> bool:
        if self.cookie_secure is not None:
            return bool(self.cookie_secure)
        return bool(getattr(settings, "SESSION_COOKIE_SECURE", False))

    @action(
        methods=["GET"],
        detail=False,
        url_path=r"login/?",
        url_name="openid_connect_login",
    )
    def login(self, request: HttpRequest, **kwargs: dict) -> HttpResponse:
        auth_server = kwargs.get("auth_server")
        client = self._get_client(auth_server=auth_server)
        if client:
            allowlist = get_login_query_param_allowlist(auth_server) - {"next"}
            extra_params = {
                key: value
                for key, value in request.query_params.items()
                if key in allowlist
            }
            raw_next = request.query_params.get("next")
            redirect_after = (
                raw_next
                if is_safe_login_redirect(raw_next, auth_server, request)
                else None
            )
            if raw_next and redirect_after is None:
                logger.warning(
                    "Rejected unsafe ?next=%r for auth_server=%r",
                    raw_next,
                    auth_server,
                )
            response = client.login(
                redirect_after=redirect_after,
                extra_params=extra_params,
            )
            # Delete only csrftoken for the current domain
            response.delete_cookie(
                "csrftoken",
                domain=getattr(settings, "CSRF_COOKIE_DOMAIN", None)
                or request.get_host().split(":")[0],
                path=getattr(settings, "CSRF_COOKIE_PATH", "/"),
                samesite=getattr(settings, "CSRF_COOKIE_SAMESITE", "Lax"),
            )
            return response
        return HttpResponseBadRequest(
            _("Unable to process OpenID connect login request."),
        )

    @action(
        methods=["GET"],
        detail=False,
        authentication_classes=[],
        renderer_classes=[JSONRenderer],
        # ``session/?`` like the other three: the router anchors patterns, so
        # without it a configured probe URL with a trailing slash 404s.
        url_path=r"session/?",
        url_name="openid_connect_session",
    )
    def session(self, request: HttpRequest, **kwargs: dict) -> HttpResponse:
        """Return the current SSO-backed browser session, without tokens.

        The action bypasses DRF authentication so anonymous requests get a
        plain JSON 401 instead of a Basic/Digest ``WWW-Authenticate`` challenge.
        Subclasses can add non-secret fields through ``get_session_data`` and
        apply deployment-specific policy through ``is_session_allowed``.
        """
        headers = {"Cache-Control": "no-store"}
        if not self.use_sso:
            return self._session_unauthorized_response(headers)

        try:
            auth = authenticate_sso(request, unique_user_field=self.sso_cookie)
        except PyJWTError:
            auth = None
        if not auth or not self.is_session_allowed(auth[0]):
            return self._session_unauthorized_response(headers)
        return Response(self.get_session_data(auth[0], request), headers=headers)

    def _session_unauthorized_response(self, headers) -> Response:
        return Response(
            {"detail": _("Authentication credentials were not provided.")},
            status=status.HTTP_401_UNAUTHORIZED,
            headers=headers,
        )

    def is_session_allowed(self, user) -> bool:
        """Return whether ``user`` may establish a session."""
        return True

    def get_session_data(self, user, request) -> dict:
        """Return the non-secret session payload for ``user``."""
        return {"username": user.username}

    @action(
        methods=["GET"],
        detail=False,
        url_path=r"logout/?",
        url_name="openid_connect_logout",
    )
    def logout(self, request: HttpRequest, **kwargs: dict) -> HttpResponse:
        auth_server = kwargs.get("auth_server")
        client = self._get_client(auth_server=auth_server)
        if client:
            # Pop (not get) so the tokens don't outlive the session they
            # belonged to. If absent (legacy session predating the callback
            # storing them), the end-session URL falls back to the bare
            # ``client_id`` + ``post_logout_redirect_uri`` baked into
            # ``END_SESSION_ENDPOINT``.
            extra_params: dict[str, str] = {}
            # ``session`` is attached by ``SessionMiddleware``; absent in
            # test rigs that build requests via ``APIRequestFactory``
            # without middleware. Treat missing session as "no stashed
            # token" — same fallback as the legacy bare end-session URL.
            session = getattr(request, "session", None)
            # Everything this provider stashed, not just the hint: the
            # redirect below may never be completed, so this is the only
            # point we control. Scoped per provider — logging out of A must
            # not sign the user out of B.
            id_token_hint = None
            if session is not None:
                for base_key in TOKEN_SESSION_BASE_KEYS:
                    value = session.pop(token_session_key(base_key, auth_server), None)
                    if base_key == ID_TOKEN_SESSION_KEY:
                        id_token_hint = value
                    session.pop(pending_token_session_key(base_key, auth_server), None)
                    # Pre-namespacing key: a write-side sweep only, so it does
                    # not reinstate the fallback read.
                    session.pop(base_key, None)
            if id_token_hint:
                extra_params["id_token_hint"] = id_token_hint

            allowlist = get_logout_query_param_allowlist(auth_server)
            for key, value in request.query_params.items():
                if key in allowlist and key not in extra_params:
                    # Server-stashed hints (e.g. id_token_hint) win on
                    # collision with caller-supplied query params.
                    extra_params[key] = value

            response = client.logout(extra_params=extra_params or None)

            if self.use_auth_backend:
                logout_backend(request)
            if self.use_sso:
                response.delete_cookie(
                    SSO_COOKIE_NAME,
                    domain=self.cookie_domain,
                    path=self.cookie_path,
                    samesite=self.cookie_samesite,
                )

            return response
        return HttpResponseBadRequest(
            _("Unable to process OpenID connect logout request."),
        )

    def _username_field_config(self) -> Tuple[str, str]:
        """
        Return (regex, help_text) for the username field, falling back
        to conservative defaults when FIELD_VALIDATION_REGEX is unset.
        The configured regex is forwarded as-is — HTML5 `pattern` already
        full-matches the input value implicitly, so the contract is that
        deployers supply a single complete pattern (top-level alternation
        with internal anchors will combine with the implicit full-match
        the same way it does in any browser-rendered form).
        """
        cfg = self.field_validation_regex.get("username", {})
        regex = cfg.get("regex") or DEFAULT_USERNAME_PATTERN
        help_text = cfg.get("help_text") or DEFAULT_USERNAME_HELP_TEXT
        return regex, help_text

    def _username_form_response(
        self,
        data: dict,
        *,
        state: Optional[str] = None,
        request: Optional[HttpRequest] = None,
        auth_server: Optional[str] = None,
        user_tokens=None,
        **response_kwargs,
    ) -> Response:
        """
        Build a Response for oidc_user_data_entry.html with the username
        regex/help text injected so the form's `pattern`/`title`
        attributes always reflect the deployed FIELD_VALIDATION_REGEX
        config, and the original auth-flow `state` rendered as a hidden
        input so the form re-submit carries it back. Callers pass the
        state once via the kwarg; the helper guarantees it's emitted on
        every render so `_clear_login_states` can drop the PKCE cache
        entry on the success path that follows.

        This is also the one place that parks the access/refresh pair for
        the round trip: the form re-POSTs only the id_token, so a pair kept
        in locals would be lost. Parking here rather than at each caller
        means the three form exits cannot disagree, and a future one that
        forgets to pass ``user_tokens`` fails closed — the user completes
        login without a pair and the account proxy answers 401, rather than
        a credential being left somewhere it should not be.
        """
        if request is not None and self.stash_oidc_tokens:
            tokens = user_tokens if isinstance(user_tokens, dict) else {}
            stash_pending_tokens(
                getattr(request, "session", None),
                auth_server,
                data.get("id_token"),
                tokens.get("access_token"),
                tokens.get("refresh_token"),
            )
        regex, help_text = self._username_field_config()
        merged = {
            **data,
            "username_pattern": regex,
            "username_help_text": help_text,
            "state": state or "",
        }
        return Response(
            merged,
            template_name=USERNAME_FORM_TEMPLATE,
            **response_kwargs,
        )

    def _check_user_uniqueness(self, user_data: dict) -> Optional[str]:
        """
        Helper function that checks if the supplied user data is unique. If user_data does not
        contain the unique user field the assumption is that the user
        exists.
        """
        for user_field in self.unique_user_filter_fields:
            if user_data.get(user_field):
                unique_field_value = user_data.get(user_field)
                unique_field = user_field + "__iexact"
                filter_kwargs = {unique_field: unique_field_value}
                if self.user_model.objects.filter(**filter_kwargs).count() > 0:
                    return user_field
        return None

    def generate_successful_response(
        self, request, user, redirect_after=None, auth_server=None
    ) -> HttpResponse:
        """
        Generates a success response for a successful Open ID Connect
        Authentication request
        """
        config = getattr(settings, "OPENID_CONNECT_VIEWSET_CONFIG", {})
        # Resolution order for the post-auth landing URL:
        #   1. explicit `redirect_after` (per-request, from id_token claim
        #      or memcached-cached `next=`) — highest priority
        #   2. per-provider TARGET_URL_AFTER_AUTH on
        #      OPENID_CONNECT_AUTH_SERVERS[auth_server]
        #   3. global REDIRECT_AFTER_AUTH on OPENID_CONNECT_VIEWSET_CONFIG
        # Lets multi-tenant deployments give each provider its own landing
        # page without mutating a shared global default.
        per_provider_target = None
        if auth_server:
            auth_servers = getattr(settings, "OPENID_CONNECT_AUTH_SERVERS", {})
            per_provider_target = auth_servers.get(auth_server, {}).get(
                "TARGET_URL_AFTER_AUTH"
            )
        response = HttpResponseRedirect(
            redirect_after or per_provider_target or config.get("REDIRECT_AFTER_AUTH")
        )

        if self.use_auth_backend:
            login(request, user, backend=self.auth_backend)

        if self.use_sso:
            sso_value = getattr(user, self.sso_cookie, getattr(user, "email", ""))
            sso_cookie = jwt.encode(
                {self.sso_cookie: sso_value},
                config.get("JWT_SECRET_KEY"),
                config.get("JWT_ALGORITHM"),
            )
            response.set_cookie(
                SSO_COOKIE_NAME,
                value=sso_cookie,
                max_age=self.cookie_max_age,
                domain=self.cookie_domain,
                path=self.cookie_path,
                httponly=self.cookie_httponly,
                secure=self._resolve_cookie_secure(),
                samesite=self.cookie_samesite,
            )

        return response

    def map_claims_to_model_field(self, user_data) -> dict:
        """
        Maps claims to the appropriate field for model ingestion
        """
        data = {}
        for k, v in user_data.items():
            if k in self.map_claim_to_model:
                data[self.map_claim_to_model[k]] = v
            else:
                data[k] = v

        # Split the name claim into `first_name` & `last_name`
        if (self.split_name_claim and "name" in user_data.keys()) and (
            "first_name" not in data.keys() or "last_name" not in data.keys()
        ):
            split_name = user_data["name"].split(" ")
            data["first_name"] = " ".join(split_name[:1])
            data["last_name"] = " ".join(split_name[1:])
        return data

    def validate_fields(self, data: dict) -> dict:
        for k, v in data.items():
            if k in self.field_validation_regex:
                field_validation_regex = self.field_validation_regex[k]
                regex = re.compile(field_validation_regex.get("regex"))
                if regex and not regex.search(data[k]):
                    # %r, not an f-string: the value is caller-supplied, and
                    # interpolating it raw lets a newline forge extra log
                    # lines. Matches the style used at the ?next= rejection.
                    logger.info("Invalid %r value %r", k, data[k])
                    raise ValueError(
                        field_validation_regex.get("help_text")
                        or f"Invalid `{k}` value `{data[k]}`"
                    )

    def _get_user_group_defaults(self, email: str) -> dict:
        groups = [key for key in self.user_default_fields.keys() if key != "default"]

        user_default = self.user_default_fields.get("default", {})
        for group in groups:
            match = re.match(group, email)
            if match:
                user_default = self.user_default_fields[group]
                break

        return user_default

    def _clean_user_data(self, user_data) -> Tuple[dict, Optional[list]]:
        user_data = {
            k: v for k, v in user_data.items() if k in self.user_creation_fields
        }
        missing_fields = set(self.required_fields).difference(set(user_data.keys()))

        # Use last_name as first_name if first_name is missing
        if "first_name" in missing_fields and "last_name" in user_data:
            user_data["first_name"] = user_data["last_name"]
            missing_fields.remove("first_name")

        # use email as username if username is missing or username is invalid
        if self.use_email_as_username:
            username_regex = re.compile(
                self.field_validation_regex["username"].get("regex")
            )
            if (
                "username" in missing_fields
                or not username_regex.search(user_data["username"])
            ) and "email" in user_data:
                username = replace_characters_in_username(
                    email_usename_to_url_safe(user_data["email"]),
                    self.replaceable_username_characters,
                    self.username_char_replacement,
                )

                # Validate retrieved username matches regex
                if "username" in self.field_validation_regex and username_regex.search(
                    username
                ):
                    user_data["username"] = username
                    if "username" in missing_fields:
                        missing_fields.remove("username")

        return user_data, missing_fields

    @staticmethod
    def _reunite_with_parked_pair(
        request: HttpRequest,
        auth_server: Optional[str],
        id_token: Optional[str],
        user_tokens,
    ):
        """Move this flow's parked pair out of the session and into hand.

        The username form re-POSTs only the id_token, so on that path the
        pair is in the session rather than in ``user_tokens``. Taken here --
        before anything that can flush the session, and unconditionally, so
        the pair cannot outlive the flow that parked it. Scoped to our
        id_token: a pair parked by a second tab still sitting on the form
        belongs to that tab and is left where it is.
        """
        tokens = user_tokens if isinstance(user_tokens, dict) else {}
        parked_access, parked_refresh = take_pending_tokens(
            getattr(request, "session", None), auth_server, id_token
        )
        if tokens.get("access_token") or not parked_access:
            return tokens
        return {
            **tokens,
            "access_token": parked_access,
            "refresh_token": parked_refresh,
        }

    def _persist_oidc_tokens(
        self,
        request: HttpRequest,
        auth_server: Optional[str],
        id_token: Optional[str],
        user_tokens,
    ) -> None:
        """Write the IdP's tokens into the session. Success exit only.

        The id_token is kept for ``logout``'s ``id_token_hint``; the
        access/refresh pair only by viewsets that call the IdP on the user's
        behalf (``stash_oidc_tokens``). Keyed by ``auth_server`` — see
        ``token_session_key``.
        """
        session = getattr(request, "session", None)
        if session is None:
            return

        # Session fixation: rotate before storing credentials. Skipped under
        # USE_AUTH_BACKEND, where Django's ``login()`` has already cycled.
        # ``cycle_key`` keeps the data, so the pending slots below survive.
        if not self.use_auth_backend and hasattr(session, "cycle_key"):
            session.cycle_key()

        tokens = user_tokens if isinstance(user_tokens, dict) else {}
        access_token = tokens.get("access_token")
        refresh_token = tokens.get("refresh_token")

        if id_token:
            session[token_session_key(ID_TOKEN_SESSION_KEY, auth_server)] = id_token
        if not self.stash_oidc_tokens:
            return
        # Written as a unit with the id_token above, clearing rather than
        # skipping. Skipping would let an earlier login's pair survive beside
        # this login's id_token — precisely the cross-identity split the
        # owner tag exists to prevent, arrived at from the other direction.
        for base_key, value in (
            (ACCESS_TOKEN_SESSION_KEY, access_token),
            (REFRESH_TOKEN_SESSION_KEY, refresh_token),
        ):
            key = token_session_key(base_key, auth_server)
            if value:
                session[key] = value
            else:
                session.pop(key, None)

    def _clear_login_states(self, server_response: dict) -> None:
        """Clear cached login states

        :param server_response: Response from authorization server
        """
        state = server_response.get("state")
        if state:
            cache.delete(state_cache_key(state))

    @action(
        methods=["POST", "GET"],
        detail=False,
        url_path=r"callback/?",
        url_name="openid_connect_callback",
    )
    def callback(self, request: HttpRequest, **kwargs: dict) -> HttpResponse:
        """Handle the IdP's redirect back, and the username form's re-POST.

        Wraps the flow so a parked token pair outlives exactly one round
        trip. ``_username_form_response`` parks one because the form
        re-POSTs only the id_token; every other way out -- an expired PKCE
        entry, an id_token that will not decode, AUTO_CREATE_USER off, a
        subclass refusing the login, success -- has to take it back, or a
        refresh token stays at rest in the session of someone who never
        signed in and so never reaches logout to clear it.

        Scoped to the id_token this request carries, which is the only pair
        that can be ours: a first callback that fails has parked nothing,
        and clearing the slots wholesale would strand a second tab.

        In a ``finally``: an id_token this library has no handler for raises
        past every ``except`` below and becomes a 500, which is an exit like
        any other and must not be the one that gets to keep a pair.
        """
        response = None
        try:
            response = self._callback(request, **kwargs)
            return response
        finally:
            if getattr(response, "template_name", None) != USERNAME_FORM_TEMPLATE:
                take_pending_tokens(
                    getattr(request, "session", None),
                    kwargs.get("auth_server"),
                    request.data.get("id_token"),
                )

    def _callback(self, request: HttpRequest, **kwargs: dict) -> HttpResponse:  # noqa
        auth_server = kwargs.get("auth_server")
        client = self._get_client(auth_server=auth_server)
        user = redirect_after = code_verifier = None
        server_response = {}

        if client:
            # The username-entry form re-POSTs to the callback URL with
            # the original (already-consumed) ?code= still on the URL
            # because action="" preserves the query string. Detect that
            # specific re-submit via the hidden marker the form sets and
            # reuse the id_token it carries instead of re-exchanging the
            # stale code (which 400s from the IdP as invalid_code). The
            # marker is a path gate, not an auth check — the id_token is
            # still verified downstream.
            is_username_form_resubmit = (
                request.method == "POST"
                and request.data.get(USERNAME_FORM_MARKER_FIELD)
                == USERNAME_FORM_MARKER_VALUE
                and request.data.get("id_token")
            )
            if is_username_form_resubmit:
                # Carry `state` forward (the form rendered it as a hidden
                # input from the original server_response) so the success
                # path's _clear_login_states can drop the PKCE cache entry
                # written by client.login(). Without this, that entry would
                # leak until cache TTL on every missing-username flow.
                server_response = {
                    "id_token": request.data.get("id_token"),
                    "state": request.data.get("state"),
                }
            elif client.response_mode == "form_post":
                server_response = request.data

            elif client.response_mode == "query":
                server_response = request.query_params

            state_value = server_response.get("state")
            if client.use_pkce and state_value:
                # Get the original code verifier for PKCE flow. We only
                # consult the namespaced key — never the raw state value
                # — so an attacker who reaches this branch with a
                # chosen `state` cannot probe arbitrary keys (e.g.
                # session IDs) for existence via cache-hit timing.
                code_verifier = cache.get(state_cache_key(state_value))

                if code_verifier is None:
                    logger.error("PKCE code verifier not found in cache")

                    return Response(
                        {
                            "error": _(
                                "Unable to validate authentication request; Kindly retry authentication process."
                            ),
                            "error_title": _(
                                "Authentication request verification failed"
                            ),
                        },
                        status=status.HTTP_401_UNAUTHORIZED,
                        template_name="oidc/oidc_unrecoverable_error.html",
                    )

            id_token = server_response.get("id_token")
            user_tokens = {}
            if not id_token and server_response.get("code"):
                try:
                    user_tokens = client.retrieve_tokens_using_auth_code(
                        server_response.get("code"), code_verifier=code_verifier
                    )
                except TokenVerificationFailed as e:
                    return Response(
                        {
                            "error": _(
                                f"Unable to retrieve ID Token; {e}. Kindly retry authentication process."
                            ),
                            "error_title": _(
                                "Authentication request verification failed"
                            ),
                        },
                        status=status.HTTP_401_UNAUTHORIZED,
                        template_name="oidc/oidc_unrecoverable_error.html",
                    )

            if user_tokens or id_token:
                try:
                    id_token = id_token or user_tokens.get("id_token")
                    decoded_id_token = client.verify_and_decode_id_token(id_token)
                    # Nothing is stored yet: refusal exits still lie below,
                    # and a refused caller must not end up with a session the
                    # proxy treats as signed in. The success exit persists.
                    user_claims = client.tokens_to_user_info(
                        self.map_claims_to_model_field(decoded_id_token),
                        id_token,
                        user_tokens.get("access_token"),
                    )
                    if user_claims.get(REDIRECT_AFTER_AUTH):
                        redirect_after = user_claims.pop(REDIRECT_AFTER_AUTH)
                    user_data = self.map_claims_to_model_field(user_claims)
                    # Custom username provided by the user in case
                    # a user with the same preferred username already exists
                    form_data = request.POST.dict()
                    provided_username = form_data.get("username")
                    if provided_username:
                        user_data.update({"username": provided_username})
                    filter_kwargs = None
                    q_objects = Q()

                    if "email" in user_data:
                        filter_kwargs = {"email__iexact": user_data.get("email")}
                    elif "emails" in user_data and user_data["emails"]:
                        emails: List[str] = user_data["emails"]
                        for email in emails:
                            q_objects |= Q(email__iexact=email)
                        user_data["email"] = user_data["emails"][0]

                    if (
                        filter_kwargs
                        and self.user_model.objects.filter(**filter_kwargs).exists()
                    ):
                        user = self.user_model.objects.get(**filter_kwargs)

                    elif (
                        q_objects and self.user_model.objects.filter(q_objects).exists()
                    ):
                        user = self.user_model.objects.get(q_objects)

                    if not user and not self.auto_create_user:
                        self._clear_login_states(server_response)
                        return Response(
                            {
                                "error": _(
                                    "The request is not authorized. Please contact the administrator."
                                ),
                                "error_title": _("Request not authorized"),
                            },
                            status=status.HTTP_401_UNAUTHORIZED,
                            template_name="oidc/oidc_unrecoverable_error.html",
                        )

                    if not user:
                        user_data, missing_fields = self._clean_user_data(user_data)
                        if missing_fields:
                            if (
                                len(missing_fields) == 1
                                and list(missing_fields)[0] == "username"
                            ):
                                data = {"id_token": id_token}
                                # %-style, not a second positional: passing
                                # an arg to a format string with no
                                # placeholder raises inside logging and the
                                # record is dropped, so this never logged.
                                logger.info("missing_fields: %r", missing_fields)
                                return self._username_form_response(
                                    data,
                                    state=server_response.get("state"),
                                    request=request,
                                    auth_server=auth_server,
                                    user_tokens=user_tokens,
                                )
                            else:
                                missing_fields = ", ".join(missing_fields)
                                logger.error(f"missing fields: {missing_fields}")
                                return Response(
                                    {
                                        "error": _(
                                            f"Missing required fields: {missing_fields}"
                                        ),
                                        "error_title": _("Missing details in ID Token"),
                                    },
                                    status=status.HTTP_400_BAD_REQUEST,
                                    template_name="oidc/oidc_unrecoverable_error.html",
                                )
                        else:
                            field = self._check_user_uniqueness(user_data)
                            if field:
                                data = {
                                    "id_token": id_token,
                                    "error": f"{field.capitalize()} field is already in use.",
                                }
                                # The field, never ``data`` -- it carries the
                                # id_token, which callback accepts from the
                                # POST body and is therefore replayable.
                                logger.info("Field already in use: %r", field)
                                return self._username_form_response(
                                    data,
                                    state=server_response.get("state"),
                                    request=request,
                                    auth_server=auth_server,
                                    user_tokens=user_tokens,
                                )

                        self.validate_fields(user_data)

                        create_data = self._get_user_group_defaults(
                            user_data.get("email")
                        )
                        create_data.update(user_data)

                        user = self.create_login_user(create_data)
                except ValueError as e:
                    stack_trace = traceback.format_exc()
                    logger.info("ValueError")
                    logger.info(stack_trace)
                    return self._username_form_response(
                        {"error": str(e), "id_token": id_token},
                        state=server_response.get("state"),
                        request=request,
                        auth_server=auth_server,
                        user_tokens=user_tokens,
                        status=status.HTTP_400_BAD_REQUEST,
                    )
                except jwt.exceptions.DecodeError:
                    return Response(
                        {
                            "error": _("Failed to decode ID Token."),
                            "error_title": _("Invalid ID Token"),
                        },
                        status=status.HTTP_401_UNAUTHORIZED,
                        template_name="oidc/oidc_unrecoverable_error.html",
                    )
                except (NonceVerificationFailed, NoJSONWebKeyFound) as e:
                    return Response(
                        {
                            "error": _(
                                f"Unable to validate authentication request; {e}. Kindly retry authentication process."
                            ),
                            "error_title": _(
                                "Authentication request verification failed"
                            ),
                        },
                        status=status.HTTP_401_UNAUTHORIZED,
                        template_name="oidc/oidc_unrecoverable_error.html",
                    )
                else:
                    if user:
                        user.last_login = timezone.now()
                        user.save(update_fields=["last_login"])
                        self._clear_login_states(server_response)
                        # Before, not after: the call below runs Django's
                        # ``login()``, which flushes the session when a
                        # different user was authenticated in it -- taking
                        # the parked slots with it. A pair the code exchange
                        # returned is already in locals and survives that;
                        # this puts the form path's pair in locals too, so
                        # both paths reach the write below the same way.
                        user_tokens = self._reunite_with_parked_pair(
                            request, auth_server, id_token, user_tokens
                        )
                        response = self.generate_successful_response(
                            request,
                            user,
                            redirect_after=redirect_after,
                            auth_server=auth_server,
                        )
                        #
                        # Only on a response that actually signed the user
                        # in. Overriding ``generate_successful_response`` to
                        # refuse a login the library accepted is the
                        # documented extension point, and the tokens are
                        # what the account proxy reads as proof of a
                        # session -- so a subclass's refusal has to be as
                        # final as one of our own.
                        if status.is_success(
                            response.status_code
                        ) or status.is_redirect(response.status_code):
                            self._persist_oidc_tokens(
                                request, auth_server, id_token, user_tokens
                            )
                        # A refusal stores nothing; ``callback`` takes the
                        # parked pair back on the way out.
                        return response
        auth_servers = list(settings.OPENID_CONNECT_AUTH_SERVERS.keys())
        default_auth_server = auth_servers[0] if auth_servers else "default"
        return Response(
            {
                "error": _("Unable to process OpenID connect authentication request."),
                "error_title": _(
                    "Unable to process OpenID connect authentication request."
                ),
                "login_url": reverse(
                    "oidc:openid_connect_login",
                    kwargs={"auth_server": default_auth_server},
                ),
            },
            status=status.HTTP_400_BAD_REQUEST,
            template_name="oidc/oidc_unrecoverable_error.html",
        )

    def create_login_user(self, user_data: dict):
        """
        Function used to create a login user from the information retrieved
        from the ID Token
        """
        raise NotImplementedError()


class UserModelOpenIDConnectViewset(BaseOpenIDConnectViewset):
    """
    OpenID Connect Viewset that utilizes the user model to create/retrieve
    request user account
    """

    user_model = get_user_model()

    def create_login_user(self, user_data: dict):
        return self.user_model.objects.create(**user_data)


class RapidProOpenIDConnectViewset(BaseOpenIDConnectViewset):
    """
    OpenID Connect Viewset tailored to work with
    RapidPro(https://github.com/rapidpro/rapidpro)
    """

    user_model = get_user_model()

    def create_login_user(self, user_data: dict):
        Org = importlib.import_module("temba").orgs.models.Org
        org_name = user_data.pop("username")
        user_data["username"] = user_data.get("email")

        org_data = {
            "name": org_name,
            "slug": Org.get_unique_slug(org_name),
            "brand": settings.DEFAULT_BRAND,
            "timezone": f"{timezone.utc}",
        }
        user = self.user_model.objects.create(**user_data)

        language = self.request.branding.get("language", settings.DEFAULT_LANGUAGE)
        user_settings = user.get_settings()
        user_settings.language = language
        user_settings.save()

        org_data.update({"created_by": user, "modified_by": user})
        org = Org.objects.create(**org_data)
        org.administrators.add(user)
        branding = org.get_branding()
        org.initialize(
            branding=branding, topup_size=branding.get("welcome_topup", 1000)
        )

        return user
