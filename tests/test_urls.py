# -*- coding: utf-8 -*-
"""
Test that oidc urls resolve.
"""

from django.test import TestCase
from django.urls import resolve, reverse

from rest_framework.renderers import JSONRenderer

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

    def test_routes_accept_an_optional_trailing_slash(self):
        """An IdP REDIRECT_URI or login link may carry a trailing slash."""
        for path in (
            "/oidc/abc/login",
            "/oidc/abc/login/",
            "/oidc/abc/callback",
            "/oidc/abc/callback/",
        ):
            with self.subTest(path=path):
                self.assertEqual(resolve(path).func.cls, UserModelOpenIDConnectViewset)


class TestUnprefixedNameRouterScope(TestCase):
    """Only ``@action`` routes are published, under their own names."""

    def _names(self, viewset):
        router = UnprefixedNameRouter(trailing_slash=False)
        router.register(r"things", viewset, basename="thing")
        return [url.name for url in router.urls]

    def test_action_names_lose_the_basename_prefix(self):
        self.assertIn(
            "openid_connect_login", self._names(UserModelOpenIDConnectViewset)
        )

    def test_crud_named_methods_are_not_routed(self):
        """A helper that happens to be called ``update`` or ``list`` on a
        ``VIEWSET_CLASS`` must not become an endpoint."""

        class HelperNamedViewset(UserModelOpenIDConnectViewset):
            def list(self, request):
                raise AssertionError

            def update(self, request, pk=None):
                raise AssertionError

        names = self._names(HelperNamedViewset)

        self.assertEqual(
            sorted(names), sorted(self._names(UserModelOpenIDConnectViewset))
        )
        self.assertFalse(any("list" in n or "detail" in n for n in names))
