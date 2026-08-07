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
from rest_framework.response import Response

from oidc.keycloak import KeycloakAccountMixin
from oidc.viewsets import UserModelOpenIDConnectViewset


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
