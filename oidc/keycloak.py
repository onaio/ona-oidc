"""
Keycloak Account REST proxy.

Keycloak-specific, and deliberately kept out of ``BaseOpenIDConnectViewset``:
the paths proxied here (``/sessions``, ``/linked-accounts``, ``/credentials``)
are Keycloak's own Account API, not anything OIDC standardises. Deployments
opt in by routing to a viewset that mixes ``KeycloakAccountMixin`` in --
see ``VIEWSET_CLASS`` -- and a deployment that does not gets no routes for
these endpoints at all.

This mirrors ``RapidProOpenIDConnectViewset``: provider-specific behaviour
lives in a subclass, the base viewset stays provider-neutral.
"""

import logging
import re
from typing import Any, Callable, Optional, Tuple

from django.http import HttpRequest, HttpResponse
from django.utils.translation import gettext as _

import jwt
import requests
from rest_framework import status
from rest_framework.decorators import action
from rest_framework.renderers import JSONRenderer
from rest_framework.response import Response

from oidc.client import EndpointNotConfigured, OpenIDClient, TokenVerificationFailed
from oidc.permissions import IsCsrfSafeAccountRequest
from oidc.utils import (
    ACCESS_TOKEN_SESSION_KEY,
    ID_TOKEN_SESSION_KEY,
    REFRESH_TOKEN_SESSION_KEY,
    token_session_key,
)
from oidc.viewsets import UserModelOpenIDConnectViewset

logger = logging.getLogger(__name__)


#: Keycloak aliases are hostname-shaped (``idp.acme.com``) and case-sensitive.
#: ``/`` stays out: these are interpolated into the upstream URL and
#: ``requests`` resolves dot segments, so a separator would let an alias form
#: path segments of its own. ``fullmatch`` rather than ``^…$``, which also
#: matches before a trailing newline.
_PROVIDER_ALIAS_RE = re.compile(r"[a-zA-Z0-9._-]+")

#: Segments ``requests`` would normalise away, walking the request out of
#: ``/linked-accounts/``. Only as a *whole* alias — ``a..b`` is ordinary.
_DOT_SEGMENTS = frozenset({".", ".."})


def _is_valid_provider_alias(alias: str) -> bool:
    """Whether ``alias`` is safe to interpolate into the Account REST path."""
    return bool(_PROVIDER_ALIAS_RE.fullmatch(alias)) and alias not in _DOT_SEGMENTS


#: Keycloak session ids are UUIDs. The dot is excluded for the same reason as
#: above: a ``..`` here would walk out of ``/sessions/``.
_SESSION_ID_RE = re.compile(r"[a-zA-Z0-9_-]+")


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


#: Single wording for "this request carries no usable OIDC session". The
#: account proxy is driven by one SPA, so the same state must not surface
#: three different strings depending on which endpoint was hit.
NO_ACTIVE_SESSION = {"error": "No active OIDC session — please sign in again."}


def _authenticated_session(request: HttpRequest, auth_server: Optional[str]):
    """The request's session if it holds an access token *for ``auth_server``*.

    Identity for the account proxy is the stashed token, not ``request.user``:
    ona-oidc only calls Django's ``login()`` when ``USE_AUTH_BACKEND`` is on,
    which is off by default, so there is no authenticated user to rely on.

    Tokens are namespaced per provider, so a caller signed in to one provider
    simply has no token here for another and is treated as having no session.
    """
    session = getattr(request, "session", None)
    if session is None or not session.get(
        token_session_key(ACCESS_TOKEN_SESSION_KEY, auth_server)
    ):
        return None
    return session


def _current_sid(request: HttpRequest, auth_server: Optional[str]) -> Optional[str]:
    """The caller's Keycloak session id, from the id_token stashed at callback.

    ``None`` when there is no session, no id_token for ``auth_server``, or no
    ``sid`` claim.
    """
    session = getattr(request, "session", None)
    if session is None:
        return None
    id_token = session.get(token_session_key(ID_TOKEN_SESSION_KEY, auth_server))
    if not id_token:
        return None
    return _sid_from_id_token(id_token)


class KeycloakAccountMixin:
    """The Keycloak Account REST proxy actions.

    Mix into a viewset deriving from ``BaseOpenIDConnectViewset``; it relies
    on ``_get_client`` from there.
    """

    #: These actions call Keycloak as the signed-in user, so they need the
    #: token pair ``callback`` would otherwise drop.
    stash_oidc_tokens = True

    def _keycloak_account_request(
        self,
        client: OpenIDClient,
        session,
        method: str,
        path_suffix: str,
    ) -> Tuple[int, Optional[dict]]:
        """
        Call Keycloak's Account REST API as the session's user,
        refreshing the stashed token pair and retrying once on 401.

        Returns ``(upstream_status, parsed_json_or_None)``; network
        failures bubble up as ``RequestException`` for the caller to
        map to 502.
        """
        # Read through ``client.auth_server`` rather than the route's kwarg:
        # the client is the thing the tokens are about to be sent to, so
        # keying off it is what makes a mismatch unrepresentable.
        access_key = token_session_key(ACCESS_TOKEN_SESSION_KEY, client.auth_server)
        refresh_key = token_session_key(REFRESH_TOKEN_SESSION_KEY, client.auth_server)

        access_token = session.get(access_key)
        if not access_token:
            return status.HTTP_401_UNAUTHORIZED, NO_ACTIVE_SESSION

        status_code, body = client.request_keycloak_account(
            access_token, method, path_suffix
        )
        if status_code != status.HTTP_401_UNAUTHORIZED:
            return status_code, body

        refresh_token = session.get(refresh_key)
        if not refresh_token:
            return status.HTTP_401_UNAUTHORIZED, body

        try:
            tokens = client.refresh_access_token(refresh_token)
        except TokenVerificationFailed:
            return (
                status.HTTP_401_UNAUTHORIZED,
                {"error": "Session expired — please sign in again."},
            )

        new_access = tokens.get("access_token")
        new_refresh = tokens.get("refresh_token")
        if new_access:
            session[access_key] = new_access
        if new_refresh:
            session[refresh_key] = new_refresh
        if not new_access:
            return status.HTTP_401_UNAUTHORIZED, body
        return client.request_keycloak_account(new_access, method, path_suffix)

    def _proxy_or_error(
        self,
        request: HttpRequest,
        auth_server,
        method: str,
        path_suffix: str,
        transform: Optional[Callable[[Any], Any]] = None,
    ) -> HttpResponse:
        """
        Shared wrapper for the proxy actions. ``transform`` runs on the
        parsed body so per-endpoint normalisation stays close to the
        action that needs it.
        """
        client = self._get_client(auth_server=auth_server)
        if client is None:
            # A DRF Response, not HttpResponseBadRequest: these actions
            # render JSON only, and an HTML body here is the one error the
            # SPA cannot read the message out of.
            return Response(
                {"error": _("Unknown auth server.")},
                status=status.HTTP_400_BAD_REQUEST,
            )
        if not client.account_endpoint:
            return Response(
                {"error": "Account endpoint not configured."},
                status=status.HTTP_503_SERVICE_UNAVAILABLE,
            )
        session = _authenticated_session(request, client.auth_server)
        if session is None:
            return Response(NO_ACTIVE_SESSION, status=status.HTTP_401_UNAUTHORIZED)
        try:
            status_code, body = self._keycloak_account_request(
                client, session, method, path_suffix
            )
        except EndpointNotConfigured as exc:
            # A missing ACCOUNT_ENDPOINT or TOKEN_ENDPOINT is our own
            # configuration gap, not the IdP being down. Reporting it as a
            # bad gateway points the investigation at Keycloak, where there
            # is nothing to find. Deliberately not bare ValueError: a
            # malformed IdP response raises JSONDecodeError, which is one
            # too, and that is upstream's problem rather than our config.
            logger.exception(exc)
            return Response(
                {"error": "Identity provider is not fully configured."},
                status=status.HTTP_503_SERVICE_UNAVAILABLE,
            )
        except requests.RequestException as exc:
            # Genuinely upstream: the IdP could not be reached. Catching bare
            # Exception here would report a bug in our own transform/flatten
            # code as "the IdP is unreachable" and send the investigation to
            # Keycloak instead of to us.
            logger.exception(exc)
            return Response(
                {"error": "Could not reach the identity provider."},
                status=status.HTTP_502_BAD_GATEWAY,
            )
        if status.is_success(status_code):
            payload = transform(body) if transform else body
            return Response(payload, status=status_code)
        return Response(
            {"error": "Identity provider rejected the request.", "upstream": body},
            status=status_code,
        )

    @action(
        methods=["GET"],
        detail=False,
        url_path="sessions",
        url_name="openid_connect_sessions",
        authentication_classes=[],
        permission_classes=[IsCsrfSafeAccountRequest],
        renderer_classes=[JSONRenderer],
    )
    def sessions_list(self, request: HttpRequest, **kwargs: dict) -> HttpResponse:
        """
        List the user's active Keycloak sessions. Flattens
        Keycloak's per-device representation into one row per
        session so the SPA renders a flat list.
        """
        # Pin ``current`` to the id_token's ``sid`` claim — Keycloak's
        # device-level flag marks every same-machine session current
        # (see _flatten_session_devices).
        current_sid = _current_sid(request, kwargs.get("auth_server"))
        return self._proxy_or_error(
            request,
            kwargs.get("auth_server"),
            "GET",
            "/sessions/devices",
            transform=lambda body: self._flatten_session_devices(body, current_sid),
        )

    @action(
        methods=["DELETE"],
        detail=False,
        url_path=r"sessions/(?P<session_id>[a-zA-Z0-9._-]+)",
        url_name="openid_connect_sessions_revoke_one",
        authentication_classes=[],
        permission_classes=[IsCsrfSafeAccountRequest],
        renderer_classes=[JSONRenderer],
    )
    def sessions_revoke_one(
        self, request: HttpRequest, session_id: str = "", **kwargs: dict
    ) -> HttpResponse:
        """Revoke one Keycloak session by id. Rejects the user's current
        session (defence in depth — the SPA already blocks this at the
        button level)."""
        if not _SESSION_ID_RE.fullmatch(session_id):
            return Response(
                {"error": "Invalid session id."},
                status=status.HTTP_400_BAD_REQUEST,
            )
        current_sid = _current_sid(request, kwargs.get("auth_server"))
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

    # Shares ``sessions_list``'s route rather than declaring its own: two
    # actions on the same path would generate two identical patterns, and
    # Django would resolve the first — leaving DELETE with a silent 405.
    # Note this also inherits sessions_list's view kwargs, so the CSRF gate
    # on this endpoint is configured there, not here.
    @sessions_list.mapping.delete
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

    @action(
        methods=["GET"],
        detail=False,
        url_path="linked-accounts",
        url_name="openid_connect_linked_list",
        authentication_classes=[],
        permission_classes=[IsCsrfSafeAccountRequest],
        renderer_classes=[JSONRenderer],
    )
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
        url_name="openid_connect_linked_unlink",
        authentication_classes=[],
        permission_classes=[IsCsrfSafeAccountRequest],
        renderer_classes=[JSONRenderer],
    )
    def linked_unlink(
        self, request: HttpRequest, provider: str = "", **kwargs: dict
    ) -> HttpResponse:
        """Unlink a broker IdP from the current user."""
        if not _is_valid_provider_alias(provider):
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
        url_name="openid_connect_linked_link_url",
        authentication_classes=[],
        permission_classes=[IsCsrfSafeAccountRequest],
        renderer_classes=[JSONRenderer],
    )
    def linked_link_url(
        self, request: HttpRequest, provider: str = "", **kwargs: dict
    ) -> HttpResponse:
        """Get Keycloak's linked-account representation for
        ``provider``, forwarded verbatim. Its ``accountLinkUri`` is the
        one-shot URL the SPA opens in a new tab to drive the
        broker-link flow."""
        if not _is_valid_provider_alias(provider):
            return Response(
                {"error": "Invalid provider alias."},
                status=status.HTTP_400_BAD_REQUEST,
            )
        return self._proxy_or_error(
            request,
            kwargs.get("auth_server"),
            "GET",
            f"/linked-accounts/{provider}",
        )

    @action(
        methods=["GET"],
        detail=False,
        url_path="credentials",
        url_name="openid_connect_credentials",
        authentication_classes=[],
        permission_classes=[IsCsrfSafeAccountRequest],
        renderer_classes=[JSONRenderer],
    )
    def credentials_list(self, request: HttpRequest, **kwargs: dict) -> HttpResponse:
        """List credential metadata (TOTP / password / recovery codes).

        Keycloak's nested wire shape (instances under
        ``userCredentialMetadatas`` → ``credential``) is forwarded
        verbatim — reshaping for rendering happens client-side in the
        SPA.
        """
        return self._proxy_or_error(
            request,
            kwargs.get("auth_server"),
            "GET",
            "/credentials",
        )

    @staticmethod
    def _flatten_session_devices(
        body: Optional[list], current_sid: Optional[str] = None
    ) -> list:
        """``[{os, device, current, sessions:[{id, browser, ...}, ...]}, ...]``
        → ``[{id, browser, os, started, ...}, ...]``.

        Field placement matters: Keycloak's ``DeviceRepresentation`` carries
        ``os``/``osVersion``/``device`` at the device level, but ``browser``
        lives on each nested ``SessionRepresentation`` (two browsers on one
        machine group under the same device, each its own session). So read
        ``browser`` from the session, not the device.

        ``current_sid`` is the ``sid`` claim from the caller's stashed
        id_token; when known, a session is current iff its id matches.
        Keycloak groups sessions by device fingerprint (OS + browser +
        IP) and flags the *device* current, so two browsers on one
        machine both read as current from Keycloak's own flags — the
        SPA rendered exactly that bug. Falls back to Keycloak's flags
        only when the sid is unavailable."""
        if not body:
            return []
        rows: list = []
        for device in body:
            os_name = device.get("os")
            device_current = bool(device.get("current"))
            for sess in device.get("sessions", []) or []:
                sid = sess.get("id")
                if current_sid:
                    is_current = sid == current_sid
                else:
                    is_current = bool(sess.get("current", device_current))
                rows.append(
                    {
                        "id": sid,
                        "browser": sess.get("browser"),
                        "os": os_name,
                        "ipAddress": sess.get("ipAddress"),
                        "started": sess.get("started"),
                        "lastAccess": sess.get("lastAccess"),
                        "current": is_current,
                        "clients": sess.get("clients", []),
                    }
                )
        return rows


class KeycloakOpenIDConnectViewset(KeycloakAccountMixin, UserModelOpenIDConnectViewset):
    """The default viewset plus the Keycloak Account REST proxy."""
