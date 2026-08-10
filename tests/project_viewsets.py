"""
Stand-in for a project-owned viewset subclass.

Mirrors how a consumer actually does this — onadata's
``OnaOpenIDConnectViewset`` subclasses the concrete viewset to refuse SSO
login for organization accounts. Kept in its own module, importing only
``oidc.viewsets``: ``oidc.urls`` resolves ``VIEWSET_CLASS`` at import time, so
a subclass module that reached back into ``oidc.urls`` would deadlock on a
circular import.
"""

from rest_framework import status
from rest_framework.decorators import action
from rest_framework.permissions import BasePermission
from rest_framework.renderers import JSONRenderer
from rest_framework.response import Response

from oidc.keycloak import KeycloakAccountMixin
from oidc.permissions import IsCsrfSafeAccountRequest
from oidc.viewsets import UserModelOpenIDConnectViewset

#: What the shipped account actions declare. Read off the mixin rather than
#: repeated, so a fixture below cannot start differing in a second way -- each
#: is meant to differ from the real route in exactly one.
GUARDED = {
    "authentication_classes": [],
    "permission_classes": [IsCsrfSafeAccountRequest],
    "renderer_classes": [JSONRenderer],
}
SESSIONS_PATH = KeycloakAccountMixin.sessions_list.url_path
CREDENTIALS_PATH = KeycloakAccountMixin.credentials_list.url_path


class InjectedViewset(UserModelOpenIDConnectViewset):
    """Subclass used to prove routing goes to the configured class."""


class PlainOverrideViewset(UserModelOpenIDConnectViewset):
    """Overrides an action the way a consumer naturally would -- and thereby
    loses its route. Exists so the deploy check has something to catch."""

    def login(self, request, **kwargs):
        return super().login(request, **kwargs)


class RedeclaredOverrideViewset(UserModelOpenIDConnectViewset):
    """The documented fix: re-apply the decorator on the override."""

    @action(
        methods=["GET"],
        detail=False,
        url_path=r"login/?",
        url_name="openid_connect_login",
    )
    def login(self, request, **kwargs):
        return super().login(request, **kwargs)


class RefusingViewset(KeycloakAccountMixin, UserModelOpenIDConnectViewset):
    """Mirrors onadata's org-account rejection: the login is refused by
    overriding ``generate_successful_response``, which is the documented
    extension point for exactly that."""

    def generate_successful_response(self, request, user, *args, **kwargs):
        return Response(
            {"error": "Organization accounts cannot sign in via SSO."},
            status=status.HTTP_403_FORBIDDEN,
        )


class NarrowedRedeclareViewset(KeycloakAccountMixin, UserModelOpenIDConnectViewset):
    """Follows E002's old hint literally: re-declares the decorator but not
    the ``@sessions_list.mapping.delete`` companion, so a fresh MethodMapper
    silently drops DELETE /sessions."""

    @action(
        methods=["GET"],
        detail=False,
        url_path=SESSIONS_PATH,
        url_name="openid_connect_sessions",
        **GUARDED,
    )
    def sessions_list(self, request, **kwargs):
        return super().sessions_list(request, **kwargs)


class RenamedRouteViewset(KeycloakAccountMixin, UserModelOpenIDConnectViewset):
    """Re-declares with a different url_name, breaking reverse()."""

    @action(
        methods=["GET"],
        detail=False,
        url_path=r"login/?",
        url_name="something_else",
    )
    def login(self, request, **kwargs):
        return super().login(request, **kwargs)


class UnguardedRedeclareViewset(KeycloakAccountMixin, UserModelOpenIDConnectViewset):
    """Route-identical, but the decorator omits the view kwargs -- so
    ``permission_classes`` falls back to the viewset default, ``AllowAny``,
    and the account proxy loses its CSRF/Origin gate."""

    @action(
        methods=["GET"],
        detail=False,
        url_path=CREDENTIALS_PATH,
        url_name="openid_connect_credentials",
    )
    def credentials_list(self, request, **kwargs):
        return super().credentials_list(request, **kwargs)


class MovedRouteViewset(KeycloakAccountMixin, UserModelOpenIDConnectViewset):
    """Re-declares under a different url_path, so the old URL 404s."""

    @action(
        methods=["GET"],
        detail=False,
        url_path="account/credentials",
        url_name="openid_connect_credentials",
        **GUARDED,
    )
    def credentials_list(self, request, **kwargs):
        return super().credentials_list(request, **kwargs)


class DetailRedeclareViewset(KeycloakAccountMixin, UserModelOpenIDConnectViewset):
    """Re-declares with ``detail=True``, which inserts a ``pk`` segment the
    caller never sends and breaks ``reverse()`` for everyone else."""

    @action(
        methods=["GET"],
        detail=True,
        url_path=CREDENTIALS_PATH,
        url_name="openid_connect_credentials",
        **GUARDED,
    )
    def credentials_list(self, request, **kwargs):
        return super().credentials_list(request, **kwargs)


class OnlyDuringMaintenance(BasePermission):
    """Stand-in for a deployment's own extra rule."""

    def has_permission(self, request, view):
        return True


class TightenedRedeclareViewset(KeycloakAccountMixin, UserModelOpenIDConnectViewset):
    """Keeps the shipped gate and adds one of its own, which is narrowing --
    not the widening E002 exists to catch."""

    @action(
        methods=["GET"],
        detail=False,
        url_path=CREDENTIALS_PATH,
        url_name="openid_connect_credentials",
        authentication_classes=[],
        permission_classes=[IsCsrfSafeAccountRequest, OnlyDuringMaintenance],
        renderer_classes=[JSONRenderer],
    )
    def credentials_list(self, request, **kwargs):
        return super().credentials_list(request, **kwargs)


class RenamedCompanionViewset(KeycloakAccountMixin, UserModelOpenIDConnectViewset):
    """Re-declares both verbs but names the DELETE handler differently. The
    route is unchanged -- ``mapping`` holds handler names, not verbs -- so
    this must not be reported."""

    @action(
        methods=["GET"],
        detail=False,
        url_path=SESSIONS_PATH,
        url_name="openid_connect_sessions",
        **GUARDED,
    )
    def sessions_list(self, request, **kwargs):
        return super().sessions_list(request, **kwargs)

    @sessions_list.mapping.delete
    def revoke_every_other_session(self, request, **kwargs):
        return super().sessions_revoke_others(request, **kwargs)


class ReskinnedFormViewset(KeycloakAccountMixin, UserModelOpenIDConnectViewset):
    """Renders the username form from its own template. The pair is still
    parked by the base method, so this exit must stay exempt from the drain
    -- keying that on the template path would strand this deployment on the
    second attempt at a username."""

    def _username_form_response(self, *args, **kwargs):
        response = super()._username_form_response(*args, **kwargs)
        response.template_name = "oidc/my_own_user_form.html"
        return response


class UnguardedAuthClassesViewset(KeycloakAccountMixin, UserModelOpenIDConnectViewset):
    """Keeps the permission and renderer kwargs, drops only
    ``authentication_classes=[]`` -- so DRF's SessionAuthentication comes
    back and enforces its own CSRF check on a route whose callers have no
    CSRF token."""

    @action(
        methods=["GET"],
        detail=False,
        url_path=CREDENTIALS_PATH,
        url_name="openid_connect_credentials",
        permission_classes=[IsCsrfSafeAccountRequest],
        renderer_classes=[JSONRenderer],
    )
    def credentials_list(self, request, **kwargs):
        return super().credentials_list(request, **kwargs)


class ComposedPermissionViewset(KeycloakAccountMixin, UserModelOpenIDConnectViewset):
    """Tightens by composing rather than by appending. ``A & B`` collapses
    into one OperandHolder, so the shipped class is no longer literally in
    the list."""

    @action(
        methods=["GET"],
        detail=False,
        url_path=CREDENTIALS_PATH,
        url_name="openid_connect_credentials",
        authentication_classes=[],
        permission_classes=[IsCsrfSafeAccountRequest & OnlyDuringMaintenance],
        renderer_classes=[JSONRenderer],
    )
    def credentials_list(self, request, **kwargs):
        return super().credentials_list(request, **kwargs)


class WidenedPermissionViewset(KeycloakAccountMixin, UserModelOpenIDConnectViewset):
    """``A | B`` reads like the composed case but is a weakening: the route
    now passes for anything B admits."""

    @action(
        methods=["GET"],
        detail=False,
        url_path=CREDENTIALS_PATH,
        url_name="openid_connect_credentials",
        authentication_classes=[],
        permission_classes=[IsCsrfSafeAccountRequest | OnlyDuringMaintenance],
        renderer_classes=[JSONRenderer],
    )
    def credentials_list(self, request, **kwargs):
        return super().credentials_list(request, **kwargs)


class ExtraVerbViewset(KeycloakAccountMixin, UserModelOpenIDConnectViewset):
    """Adds a verb to a route it otherwise re-declares faithfully."""

    @action(
        methods=["GET", "HEAD"],
        detail=False,
        url_path=CREDENTIALS_PATH,
        url_name="openid_connect_credentials",
        **GUARDED,
    )
    def credentials_list(self, request, **kwargs):
        return super().credentials_list(request, **kwargs)
