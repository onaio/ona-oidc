# -*- coding: utf-8 -*-
"""
Test that oidc urls resolve.
"""

from django.test import TestCase, override_settings
from django.urls import resolve, reverse

from rest_framework.renderers import JSONRenderer
from rest_framework.response import Response
from rest_framework.test import APIRequestFactory

from oidc.viewsets import OIDCTemplateHTMLRenderer, UserModelOpenIDConnectViewset


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


def _render_page(template_name):
    response = Response({"error": "boom"}, template_name=template_name)
    request = APIRequestFactory().get("/")
    return OIDCTemplateHTMLRenderer().render(
        response.data,
        renderer_context={
            "request": request,
            "response": response,
            "view": UserModelOpenIDConnectViewset(),
        },
    )


class TestShippedTemplates(TestCase):
    """The username form and the error page extend a base template."""

    @override_settings(
        TEMPLATES=[
            {
                "BACKEND": "django.template.backends.django.DjangoTemplates",
                "DIRS": [],
                "APP_DIRS": True,
                "OPTIONS": {"context_processors": []},
            }
        ]
    )
    def test_they_render_from_the_packaged_fallback_alone(self):
        for name in (
            "oidc/oidc_unrecoverable_error.html",
            "oidc/oidc_user_data_entry.html",
        ):
            with self.subTest(template=name):
                self.assertIn('name="viewport"', _render_page(name))

    def test_the_viewset_renders_pages_with_the_fallback_aware_renderer(self):
        """The renderer is what makes a fresh install render; the tests above
        call it directly."""
        self.assertIn(
            OIDCTemplateHTMLRenderer, UserModelOpenIDConnectViewset.renderer_classes
        )

    def test_a_projects_own_base_template_wins(self):
        """The suite's fixture base.html is on DIRS, standing in for one a
        project provides. The package must not claim the global name."""
        page = _render_page("oidc/oidc_unrecoverable_error.html")

        self.assertIn("Le styles", page)
        self.assertIn("boom", page)
