# -*- coding: utf-8 -*-
"""
Test that oidc urls resolve.
"""

from django.contrib.auth.models import User
from django.test import TestCase
from django.urls import resolve, reverse

from rest_framework.renderers import JSONRenderer
from rest_framework.viewsets import ModelViewSet

from oidc.routers import UnprefixedNameRouter
from oidc.viewsets import UserModelOpenIDConnectViewset


class TestUrls(TestCase):
    def setUp(self):
        TestCase().setUp()

    def test_default_urls(self):
        """Test openid connect urls resolve correctly."""

        # Login
        url = reverse("oidc:openid_connect_login", kwargs={"auth_server": "abc"})
        self.assertEqual(url, "/oidc/abc/login")
        view, _args, _kwargs = resolve(url)
        self.assertEqual(view.cls, UserModelOpenIDConnectViewset)
        self.assertEqual(view.actions, {"get": "login"})

        # Callback
        url = reverse("oidc:openid_connect_callback", kwargs={"auth_server": "abc"})
        self.assertEqual(url, "/oidc/abc/callback")
        view, _args, _kwargs = resolve(url)
        self.assertEqual(view.cls, UserModelOpenIDConnectViewset)
        self.assertEqual(view.actions, {"get": "callback", "post": "callback"})

        # Logout
        url = reverse("oidc:openid_connect_logout", kwargs={"auth_server": "abc"})
        self.assertEqual(url, "/oidc/abc/logout")
        view, _args, _kwargs = resolve(url)
        self.assertEqual(view.cls, UserModelOpenIDConnectViewset)
        self.assertEqual(view.actions, {"get": "logout"})

        # Session
        url = reverse("oidc:openid_connect_session", kwargs={"auth_server": "abc"})
        self.assertEqual(url, "/oidc/abc/session")
        view, _args, _kwargs = resolve(url)
        self.assertEqual(view.cls, UserModelOpenIDConnectViewset)
        self.assertEqual(view.actions, {"get": "session"})
        self.assertEqual(view.initkwargs["authentication_classes"], [])
        self.assertEqual(view.initkwargs["renderer_classes"], [JSONRenderer])


class TestUnprefixedNameRouterScope(TestCase):
    """The router drops the ``{basename}-`` prefix so this package's
    ``@action`` names survive. That must not extend to DRF's own
    ``{basename}-list``/``-detail``: a ``VIEWSET_CLASS`` with CRUD methods
    would come out as a bare ``list``/``detail``, which collides across
    routers in one namespace and breaks hyperlinked serializers reversing
    ``<model>-detail``."""

    def _names(self, viewset):
        router = UnprefixedNameRouter(trailing_slash=False)
        router.register(r"things", viewset, basename="thing")
        return [url.name for url in router.urls]

    def test_action_names_lose_the_basename_prefix(self):
        self.assertIn(
            "openid_connect_login", self._names(UserModelOpenIDConnectViewset)
        )

    def test_crud_routes_keep_drfs_naming(self):
        class ThingViewSet(ModelViewSet):
            queryset = User.objects.all()
            serializer_class = None

        names = self._names(ThingViewSet)
        self.assertIn("thing-list", names)
        self.assertIn("thing-detail", names)
