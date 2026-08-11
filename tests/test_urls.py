# -*- coding: utf-8 -*-
"""
Test that oidc urls resolve.
"""

from django.template.loader import get_template
from django.test import TestCase, override_settings
from django.urls import resolve, reverse

from rest_framework.renderers import JSONRenderer

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


class TestShippedTemplatesRenderStandalone(TestCase):
    """The package renders two pages in a browser, and both extend
    ``base.html``. The suite puts a fixture one on ``DIRS``, so nothing here
    exercised what a project that installed the package and followed the
    README actually gets -- which was TemplateDoesNotExist, i.e. a bare 500
    on the username form and on every unrecoverable-error page."""

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
    def test_they_render_with_app_dirs_alone(self):
        for name in (
            "oidc/oidc_unrecoverable_error.html",
            "oidc/oidc_user_data_entry.html",
        ):
            with self.subTest(template=name):
                get_template(name).render({})
