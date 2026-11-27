"""Tests for module oidc.apps"""

from django.apps import apps
from django.core.exceptions import ImproperlyConfigured
from django.test import TestCase
from django.test.utils import override_settings


class ReadyTestCase(TestCase):
    """Tests for method ready"""

    @override_settings(
        CACHES={"default": {"BACKEND": "django.core.cache.backends.dummy.DummyCache"}},
        OPENID_CONNECT_AUTH_SERVERS={"default": {"CLIENT_ID": "client"}},
    )
    def test_startup_fails_when_binding_cannot_be_stored(self):
        """Enforced binding on an unsupported cache stops startup."""
        with self.assertRaises(ImproperlyConfigured):
            apps.get_app_config("oidc").ready()

    @override_settings(
        CACHES={
            "default": {"BACKEND": "django.core.cache.backends.locmem.LocMemCache"}
        },
        OPENID_CONNECT_AUTH_SERVERS={"default": {"CLIENT_ID": "client"}},
    )
    def test_startup_succeeds_on_a_supported_cache(self):
        """A supported cache starts without error."""
        apps.get_app_config("oidc").ready()
