"""
Stand-ins for a project-owned viewset subclass.

Mirrors how a consumer actually does this -- onadata's
``OnaOpenIDConnectViewset`` subclasses the concrete viewset to refuse SSO
login for organization accounts. Kept in its own module, importing only
``oidc.viewsets``: ``oidc.urls`` resolves ``VIEWSET_CLASS`` at import time, so
a subclass module that reached back into ``oidc.urls`` would deadlock on a
circular import.
"""

from rest_framework.decorators import action
from rest_framework.renderers import JSONRenderer

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


class DroppedViewKwargsViewset(UserModelOpenIDConnectViewset):
    """Re-declares the route but drops the view kwargs the base set.

    Path, name and verbs all still match, so a comparison on those alone
    reports nothing -- while ``session`` has quietly regained the default
    authentication and renderer classes it was declared without.
    """

    @action(
        methods=["GET"],
        detail=False,
        url_path=r"session/?",
        url_name="openid_connect_session",
    )
    def session(self, request, **kwargs):
        return super().session(request, **kwargs)


class WidenedViewKwargsViewset(UserModelOpenIDConnectViewset):
    """Adds to the base's view kwargs rather than dropping them. Allowed --
    the check compares as subsets so a subclass may tighten, not loosen."""

    @action(
        methods=["GET"],
        detail=False,
        authentication_classes=[],
        renderer_classes=[JSONRenderer],
        url_path=r"session/?",
        url_name="openid_connect_session",
    )
    def session(self, request, **kwargs):
        return super().session(request, **kwargs)
