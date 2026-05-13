"""
oidc Viewsets module
"""

import importlib
import logging
import re
import traceback
from typing import Any, Callable, List, Mapping, Optional, Tuple

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
    email_usename_to_url_safe,
    get_login_query_param_allowlist,
    get_logout_query_param_allowlist,
    get_viewset_config,
    is_safe_login_redirect,
    replace_characters_in_username,
    str_to_bool,
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

# Defaults used when FIELD_VALIDATION_REGEX has no "username" entry.
# Kept conservative so the rendered form matches the legacy template
# behaviour for deployments that haven't customized validation.
DEFAULT_USERNAME_PATTERN = r"^[A-Za-z0-9_]*$"
DEFAULT_USERNAME_HELP_TEXT = "Username should not contain . @ - symbols"

logger = logging.getLogger(__name__)


_PROVIDER_ALIAS_RE = re.compile(r"^[a-z0-9_-]+$")


def _sid_from_id_token(id_token: str) -> Optional[str]:
    """Decode the ``sid`` claim from an id_token *without* verifying the
    signature. The token was already verified at callback time and
    stashed in the user's session; we only need the session-id claim
    to power the revoke-current guard."""
    try:
        unverified = jwt.decode(id_token, options={"verify_signature": False})
    except jwt.exceptions.InvalidTokenError:
        return None
    return unverified.get("sid")


class BaseOpenIDConnectViewset(viewsets.ViewSet):
    """
    BaseOpenIDConnectViewset: Base viewset that implements login and logout
    Open ID Connect Functionality.
    """

    permission_classes = [permissions.AllowAny]
    renderer_classes = [JSONRenderer, TemplateHTMLRenderer]
    user_model = None

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

    @action(methods=["GET"], detail=False)
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

    @action(methods=["GET"], detail=False)
    def logout(self, request: HttpRequest, **kwargs: dict) -> HttpResponse:
        auth_server = kwargs.get("auth_server")
        client = self._get_client(auth_server=auth_server)
        if client:
            # Pop (not get) so the token doesn't outlive the session
            # it belonged to. If absent (legacy session predating the
            # callback storing it), the end-session URL falls back to
            # the bare ``client_id`` + ``post_logout_redirect_uri``
            # baked into ``END_SESSION_ENDPOINT``.
            extra_params: dict[str, str] = {}
            # ``session`` is attached by ``SessionMiddleware``; absent in
            # test rigs that build requests via ``APIRequestFactory``
            # without middleware. Treat missing session as "no stashed
            # token" — same fallback as the legacy bare end-session URL.
            session = getattr(request, "session", None)
            id_token_hint = session.pop("oidc_id_token", None) if session else None
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

    # Fields the SPA is allowed to update on the Keycloak Account REST
    # API. Anything else in the request body is dropped at this
    # boundary. Notably absent: ``username`` (would diverge from the
    # OnaData identity ona-oidc looks up by) and any role/group
    # attributes (Account API rejects them, but be explicit).
    _ACCOUNT_UPDATE_ALLOWED_FIELDS = frozenset({"email", "firstName", "lastName"})

    def _keycloak_account_request(
        self,
        client: OpenIDClient,
        session,
        method: str,
        path_suffix: str,
        json_body: Optional[Mapping[str, Any]] = None,
    ) -> Tuple[int, Optional[dict]]:
        """
        Call Keycloak's Account REST API on behalf of the user identified
        by the stashed ``oidc_access_token``. On 401 the helper mints a
        fresh access_token via the stashed ``oidc_refresh_token``, writes
        the new pair back to the session, and retries once.

        Returns ``(upstream_status, parsed_json_or_None)``. Network
        failures bubble up as ``RequestException`` — the caller is
        expected to translate them to 502.
        """
        access_token = session.get("oidc_access_token")
        if not access_token:
            return 401, {"error": "No active OIDC session."}

        status_code, body = client.request_keycloak_account(
            access_token, method, path_suffix, json_body
        )
        if status_code != 401:
            return status_code, body

        refresh_token = session.get("oidc_refresh_token")
        if not refresh_token:
            return 401, body

        try:
            tokens = client.refresh_access_token(refresh_token)
        except TokenVerificationFailed:
            return 401, {"error": "Session expired — please sign in again."}

        new_access = tokens.get("access_token")
        new_refresh = tokens.get("refresh_token")
        if new_access:
            session["oidc_access_token"] = new_access
        if new_refresh:
            session["oidc_refresh_token"] = new_refresh
        if not new_access:
            return 401, body
        return client.request_keycloak_account(
            new_access, method, path_suffix, json_body
        )

    def _proxy_or_error(
        self,
        request: HttpRequest,
        auth_server,
        method: str,
        path_suffix: str,
        json_body: Optional[Mapping[str, Any]] = None,
        transform: Optional[Callable[[Any], Any]] = None,
    ) -> HttpResponse:
        """
        Boilerplate wrapper for read/write proxy actions: resolve client,
        validate session, dispatch to ``_keycloak_account_request``,
        return Response. ``transform`` runs on the parsed body before
        it's returned so per-endpoint normalisation (e.g. flattening
        session devices) stays close to the action that needs it.
        """
        client = self._get_client(auth_server=auth_server)
        if client is None:
            return HttpResponseBadRequest(
                _("Unable to process OpenID connect account request.")
            )
        if not client.account_endpoint:
            return Response(
                {"error": "Account endpoint not configured."},
                status=status.HTTP_503_SERVICE_UNAVAILABLE,
            )
        session = getattr(request, "session", None)
        if session is None:
            return Response(
                {"error": "No active session."},
                status=status.HTTP_401_UNAUTHORIZED,
            )
        try:
            status_code, body = self._keycloak_account_request(
                client, session, method, path_suffix, json_body
            )
        except Exception as exc:
            logger.exception(exc)
            return Response(
                {"error": "Could not reach the identity provider."},
                status=status.HTTP_502_BAD_GATEWAY,
            )
        if 200 <= status_code < 300:
            payload = transform(body) if transform else body
            return Response(payload, status=status_code)
        return Response(
            {"error": "Identity provider rejected the request.", "upstream": body},
            status=status_code,
        )

    @action(methods=["GET"], detail=False, url_path="sessions")
    def sessions_list(self, request: HttpRequest, **kwargs: dict) -> HttpResponse:
        """
        List the user's active Keycloak sessions. Flattens
        Keycloak's per-device representation into one row per
        session so the SPA renders a flat list.
        """
        return self._proxy_or_error(
            request,
            kwargs.get("auth_server"),
            "GET",
            "/sessions/devices",
            transform=self._flatten_session_devices,
        )

    @action(
        methods=["DELETE"],
        detail=False,
        url_path=r"sessions/(?P<session_id>[a-zA-Z0-9._-]+)",
    )
    def sessions_revoke_one(
        self, request: HttpRequest, session_id: str = "", **kwargs: dict
    ) -> HttpResponse:
        """Revoke one Keycloak session by id. Rejects the user's current
        session (defence in depth — the SPA already blocks this at the
        button level)."""
        session = getattr(request, "session", None)
        if session is not None:
            id_token = session.get("oidc_id_token")
            if id_token:
                current_sid = _sid_from_id_token(id_token)
                if current_sid and current_sid == session_id:
                    return Response(
                        {
                            "error": (
                                "Cannot revoke the current session via this "
                                "endpoint; use sign-out instead."
                            )
                        },
                        status=status.HTTP_409_CONFLICT,
                    )
        return self._proxy_or_error(
            request,
            kwargs.get("auth_server"),
            "DELETE",
            f"/sessions/{session_id}",
        )

    @action(methods=["DELETE"], detail=False, url_path="sessions")
    def sessions_revoke_others(
        self, request: HttpRequest, **kwargs: dict
    ) -> HttpResponse:
        """Revoke every Keycloak session except the current one."""
        return self._proxy_or_error(
            request,
            kwargs.get("auth_server"),
            "DELETE",
            "/sessions?current=false",
        )

    @action(methods=["GET"], detail=False, url_path="linked-accounts")
    def linked_list(self, request: HttpRequest, **kwargs: dict) -> HttpResponse:
        """List broker IdPs configured on the realm with their connected
        state for the current user."""
        return self._proxy_or_error(
            request,
            kwargs.get("auth_server"),
            "GET",
            "/linked-accounts",
        )

    @action(
        methods=["DELETE"],
        detail=False,
        url_path=r"linked-accounts/(?P<provider>[^/]+)",
    )
    def linked_unlink(
        self, request: HttpRequest, provider: str = "", **kwargs: dict
    ) -> HttpResponse:
        """Unlink a broker IdP from the current user."""
        if not _PROVIDER_ALIAS_RE.match(provider):
            return Response(
                {"error": "Invalid provider alias."},
                status=status.HTTP_400_BAD_REQUEST,
            )
        return self._proxy_or_error(
            request,
            kwargs.get("auth_server"),
            "DELETE",
            f"/linked-accounts/{provider}",
        )

    @action(
        methods=["GET"],
        detail=False,
        url_path=r"linked-accounts/(?P<provider>[^/]+)/link-url",
    )
    def linked_link_url(
        self, request: HttpRequest, provider: str = "", **kwargs: dict
    ) -> HttpResponse:
        """Get a one-shot URL the SPA opens in a new tab to drive
        Keycloak's broker-link flow for ``provider``."""
        if not _PROVIDER_ALIAS_RE.match(provider):
            return Response(
                {"error": "Invalid provider alias."},
                status=status.HTTP_400_BAD_REQUEST,
            )
        return self._proxy_or_error(
            request,
            kwargs.get("auth_server"),
            "GET",
            f"/linked-accounts/{provider}",
            transform=lambda body: (
                {"url": body.get("accountLinkUri")} if body else None
            ),
        )

    @action(methods=["GET"], detail=False, url_path="credentials")
    def credentials_list(self, request: HttpRequest, **kwargs: dict) -> HttpResponse:
        """List credential metadata (TOTP / password / recovery codes).

        Keycloak's Account REST returns each credential category with the
        configured instances nested under ``userCredentialMetadatas`` →
        ``credential``. SPAs would have to walk two levels just to ask
        "does the user have a TOTP?" — so we flatten to a single
        ``credentials`` array of ``{id, userLabel?, createdDate?}`` and
        forward only the top-level fields the SPA actually renders.
        """
        return self._proxy_or_error(
            request,
            kwargs.get("auth_server"),
            "GET",
            "/credentials",
            transform=self._flatten_credentials,
        )

    @staticmethod
    def _flatten_credentials(body: Optional[list]) -> list:
        """Reshape Keycloak's credential-metadata array for the SPA.

        Keycloak Account REST shape::

            [
              {
                "type": "otp",
                "category": "two-factor",
                "displayName": "otp-display-name",
                "userCredentialMetadatas": [
                  {"credential": {"id": "...", "userLabel": "...",
                                  "createdDate": 1700000000000}, ...}
                ],
                ...
              },
              ...
            ]

        SPA shape::

            [{"type", "category", "displayName",
              "credentials": [{"id", "userLabel", "createdDate"}]}, ...]
        """
        if not body:
            return []
        out: list = []
        for entry in body:
            instances = []
            for meta in entry.get("userCredentialMetadatas", []) or []:
                cred = (meta or {}).get("credential") or {}
                cred_id = cred.get("id")
                if not cred_id:
                    # A metadata row without an id is unusable — the SPA
                    # uses id as the React key and as the DELETE path, so
                    # silently dropping it is safer than rendering a row
                    # that can't be acted on.
                    continue
                row = {"id": cred_id}
                user_label = cred.get("userLabel")
                if user_label:
                    row["userLabel"] = user_label
                created = cred.get("createdDate")
                if created is not None:
                    row["createdDate"] = created
                instances.append(row)
            out.append(
                {
                    "type": entry.get("type"),
                    "category": entry.get("category"),
                    "displayName": entry.get("displayName"),
                    "credentials": instances,
                }
            )
        return out

    @staticmethod
    def _flatten_session_devices(body: Optional[list]) -> list:
        """``[{browser, os, sessions:[{id, started, ...}, ...]}, ...]``
        → ``[{id, browser, os, started, ...}, ...]``."""
        if not body:
            return []
        rows: list = []
        for device in body:
            browser = device.get("browser")
            os_name = device.get("os")
            for sess in device.get("sessions", []) or []:
                rows.append(
                    {
                        "id": sess.get("id"),
                        "browser": browser,
                        "os": os_name,
                        "ipAddress": sess.get("ipAddress"),
                        "started": sess.get("started"),
                        "lastAccess": sess.get("lastAccess"),
                        "current": bool(sess.get("current")),
                        "clients": sess.get("clients", []),
                    }
                )
        return rows

    @action(methods=["POST"], detail=False)
    def account(self, request: HttpRequest, **kwargs: dict) -> HttpResponse:
        """
        Proxy a profile update from the SPA to Keycloak's Account REST
        API. Uses the access_token stashed in the Django session at
        callback time; if Keycloak rejects it as expired, refresh via
        the stashed refresh_token and retry once.

        Body: JSON object with any of ``email`` / ``firstName`` /
        ``lastName``. Everything else is silently dropped.

        Returns:
        - 200 ``{"success": true}`` on Keycloak 2xx.
        - 401 if no session-stashed access_token, or if refresh fails.
        - Upstream Keycloak status + body for any other non-2xx.
        """
        auth_server = kwargs.get("auth_server")
        client = self._get_client(auth_server=auth_server)
        if client is None:
            return HttpResponseBadRequest(
                _("Unable to process OpenID connect account update.")
            )
        if not client.account_endpoint:
            return Response(
                {"error": "Account endpoint not configured."},
                status=status.HTTP_503_SERVICE_UNAVAILABLE,
            )

        session = getattr(request, "session", None)
        if session is None:
            return Response(
                {"error": "No active session."},
                status=status.HTTP_401_UNAUTHORIZED,
            )
        access_token = session.get("oidc_access_token")
        if not access_token:
            return Response(
                {"error": "No active OIDC session — please sign in again."},
                status=status.HTTP_401_UNAUTHORIZED,
            )

        # Restrict to the allowlist at the boundary. ``request.data``
        # is a QueryDict for form bodies and a plain dict for JSON;
        # ``.items()`` works for both.
        raw = request.data if hasattr(request, "data") else {}
        payload = {
            key: value
            for key, value in raw.items()
            if key in self._ACCOUNT_UPDATE_ALLOWED_FIELDS
        }
        if not payload:
            return Response(
                {
                    "error": (
                        "No allowed fields supplied. Allowed: "
                        + ", ".join(sorted(self._ACCOUNT_UPDATE_ALLOWED_FIELDS))
                    )
                },
                status=status.HTTP_400_BAD_REQUEST,
            )

        try:
            status_code, body = self._keycloak_account_request(
                client, session, "POST", "", json_body=payload
            )
        except Exception as exc:
            logger.exception(exc)
            return Response(
                {"error": "Could not reach the identity provider."},
                status=status.HTTP_502_BAD_GATEWAY,
            )

        if 200 <= status_code < 300:
            return Response({"success": True}, status=status.HTTP_200_OK)

        return Response(
            {
                "error": "Identity provider rejected the update.",
                "upstream": body,
            },
            status=status_code,
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
        """
        regex, help_text = self._username_field_config()
        merged = {
            **data,
            "username_pattern": regex,
            "username_help_text": help_text,
            "state": state or "",
        }
        return Response(
            merged,
            template_name="oidc/oidc_user_data_entry.html",
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
            sso_cookie = jwt.encode(
                {"email": getattr(user, self.sso_cookie, "email")},
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
                    logger.info(f"Invalid `{k}` value `{data[k]}`")
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

    def _clear_login_states(self, server_response: dict) -> None:
        """Clear cached login states

        :param server_response: Response from authorization server
        """
        state = server_response.get("state")
        if state:
            cache.delete(state_cache_key(state))

    @action(methods=["POST", "GET"], detail=False)
    def callback(self, request: HttpRequest, **kwargs: dict) -> HttpResponse:  # noqa
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
                    # Stash the raw id_token in the Django session so
                    # the logout action below can replay it as
                    # `id_token_hint` on the Keycloak end-session URL.
                    # Without it, Keycloak 18+ shows the logout-confirm
                    # screen even when `client_id` + a whitelisted
                    # `post_logout_redirect_uri` are passed.
                    # ``session`` is attached by ``SessionMiddleware``;
                    # absent in callback rigs that build requests via
                    # ``APIRequestFactory`` without middleware, so guard
                    # the write the same way ``logout`` guards the read.
                    callback_session = getattr(request, "session", None)
                    if id_token and callback_session is not None:
                        callback_session["oidc_id_token"] = id_token
                    # Also stash the access_token + refresh_token so
                    # the ``account`` action can call the Keycloak
                    # Account REST API on behalf of the user (and
                    # refresh on 401 expiry). ``user_tokens`` is the
                    # raw token-endpoint response dict.
                    if callback_session is not None and isinstance(user_tokens, dict):
                        access_token = user_tokens.get("access_token")
                        refresh_token = user_tokens.get("refresh_token")
                        if access_token:
                            callback_session["oidc_access_token"] = access_token
                        if refresh_token:
                            callback_session["oidc_refresh_token"] = refresh_token
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
                                logger.info("missing_fields: ", missing_fields)
                                return self._username_form_response(
                                    data, state=server_response.get("state")
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
                                logger.info(data)
                                return self._username_form_response(
                                    data, state=server_response.get("state")
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
                        return self.generate_successful_response(
                            request,
                            user,
                            redirect_after=redirect_after,
                            auth_server=auth_server,
                        )
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
