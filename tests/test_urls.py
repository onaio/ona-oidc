# -*- coding: utf-8 -*-
"""
Test that oidc urls resolve.
"""
from django.test import TestCase
from django.urls import reverse, resolve

from oidc.viewsets import UserModelOpenIDConnectViewset


class TestUrls(TestCase):
    def setUp(self):
        TestCase().setUp()

    def test_default_urls(self):
        """Test openid connect urls resolve correctly."""

        # Login
        url = reverse('openid_connect_login', kwargs={'auth_server': 'abc'})
        self.assertEqual(url, '/oidc/abc/login')
        view, _args, _kwargs = resolve(url)
        self.assertEqual(view.cls, UserModelOpenIDConnectViewset)
        self.assertEqual(view.actions, {'get': 'login'})

        # Callback
        url = reverse('openid_connect_callback', kwargs={'auth_server': 'abc'})
        self.assertEqual(url, '/oidc/abc/callback')
        view, _args, _kwargs = resolve(url)
        self.assertEqual(view.cls, UserModelOpenIDConnectViewset)
        self.assertEqual(view.actions, {'get': 'callback', 'post': 'callback'})

        # Logout
        url = reverse('openid_connect_logout', kwargs={'auth_server': 'abc'})
        self.assertEqual(url, '/oidc/abc/logout')
        view, _args, _kwargs = resolve(url)
        self.assertEqual(view.cls, UserModelOpenIDConnectViewset)
        self.assertEqual(view.actions, {'get': 'logout'})
