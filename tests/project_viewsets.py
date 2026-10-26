"""
Stand-ins for a project-owned viewset subclass.

Mirrors how a consumer subclasses the concrete viewset. Kept in its own
module, importing only
``oidc.viewsets``: ``oidc.urls`` resolves ``VIEWSET_CLASS`` at import time, so
a subclass module that reached back into ``oidc.urls`` would fail on a
circular import.
"""

from rest_framework.authentication import BasicAuthentication
from rest_framework.decorators import action
from rest_framework.permissions import AllowAny, IsAdminUser, IsAuthenticated
from rest_framework.renderers import JSONRenderer, TemplateHTMLRenderer

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
    """Adds a renderer to ``session``. Allowed: a renderer is a response
    format, not a way in."""

    @action(
        methods=["GET"],
        detail=False,
        authentication_classes=[],
        renderer_classes=[JSONRenderer, TemplateHTMLRenderer],
        url_path=r"session/?",
        url_name="openid_connect_session",
    )
    def session(self, request, **kwargs):
        return super().session(request, **kwargs)


class AddedAuthenticationViewset(UserModelOpenIDConnectViewset):
    """Adds an authentication class to ``session``. Each one is another way
    in, so this widens the route rather than tightening it."""

    @action(
        methods=["GET"],
        detail=False,
        authentication_classes=[BasicAuthentication],
        renderer_classes=[JSONRenderer],
        url_path=r"session/?",
        url_name="openid_connect_session",
    )
    def session(self, request, **kwargs):
        return super().session(request, **kwargs)


class MovedPathViewset(UserModelOpenIDConnectViewset):
    @action(
        methods=["GET"],
        detail=False,
        url_path=r"signin/?",
        url_name="openid_connect_login",
    )
    def login(self, request, **kwargs):
        return super().login(request, **kwargs)


class DetailRouteViewset(UserModelOpenIDConnectViewset):
    @action(
        methods=["GET"],
        detail=True,
        url_path=r"login/?",
        url_name="openid_connect_login",
    )
    def login(self, request, **kwargs):
        return super().login(request, **kwargs)


class LostVerbViewset(UserModelOpenIDConnectViewset):
    """Re-declares ``callback`` with GET only; the base also accepts POST."""

    @action(
        methods=["GET"],
        detail=False,
        url_path=r"callback/?",
        url_name="openid_connect_callback",
    )
    def callback(self, request, **kwargs):
        return super().callback(request, **kwargs)


class GatedViewset(UserModelOpenIDConnectViewset):
    """A project base that puts a permission on one of its own actions."""

    @action(
        methods=["GET"],
        detail=False,
        permission_classes=[IsAuthenticated],
        url_path=r"profile/?",
        url_name="profile",
    )
    def profile(self, request, **kwargs):
        return super().session(request, **kwargs)


class TightenedPermissionViewset(GatedViewset):
    @action(
        methods=["GET"],
        detail=False,
        permission_classes=[IsAuthenticated & IsAdminUser],
        url_path=r"profile/?",
        url_name="profile",
    )
    def profile(self, request, **kwargs):
        return super().profile(request, **kwargs)


class LoosenedPermissionViewset(GatedViewset):
    @action(
        methods=["GET"],
        detail=False,
        permission_classes=[IsAuthenticated | AllowAny],
        url_path=r"profile/?",
        url_name="profile",
    )
    def profile(self, request, **kwargs):
        return super().profile(request, **kwargs)


class ComposedGatedViewset(UserModelOpenIDConnectViewset):
    """A project base whose action composes its permission with ``&``."""

    @action(
        methods=["GET"],
        detail=False,
        permission_classes=[IsAuthenticated & IsAdminUser],
        url_path=r"profile/?",
        url_name="profile",
    )
    def profile(self, request, **kwargs):
        return super().session(request, **kwargs)


class RedeclaredComposedViewset(ComposedGatedViewset):
    @action(
        methods=["GET"],
        detail=False,
        permission_classes=[IsAuthenticated & IsAdminUser],
        url_path=r"profile/?",
        url_name="profile",
    )
    def profile(self, request, **kwargs):
        return super().profile(request, **kwargs)


class DroppedComposedViewset(ComposedGatedViewset):
    @action(
        methods=["GET"],
        detail=False,
        url_path=r"profile/?",
        url_name="profile",
    )
    def profile(self, request, **kwargs):
        return super().profile(request, **kwargs)
