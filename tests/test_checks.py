# -*- coding: utf-8 -*-
"""
Test the deploy checks registered from ``oidcConfig.ready``.
"""

import sys

from django.test import TestCase, override_settings

from oidc.checks import check_actions_survive_subclassing

BASE = "oidc.viewsets.UserModelOpenIDConnectViewset"
FIXTURES = "tests.project_viewsets."


def _viewset_class(dotted_path):
    """``oidc.urls`` reads VIEWSET_CLASS at import time, so the check's own
    import of it has to see the overridden setting -- drop the cached module
    and let it re-resolve."""
    sys.modules.pop("oidc.urls", None)
    return override_settings(
        OPENID_CONNECT_VIEWSET_CONFIG={"VIEWSET_CLASS": dotted_path}
    )


class TestActionsSurviveSubclassing(TestCase):
    def _errors(self, dotted_path):
        with _viewset_class(dotted_path):
            return check_actions_survive_subclassing(None)

    def test_the_shipped_viewset_is_clean(self):
        self.assertEqual(self._errors(BASE), [])

    def test_a_subclass_that_adds_nothing_is_clean(self):
        self.assertEqual(self._errors(FIXTURES + "InjectedViewset"), [])

    def test_a_plain_override_loses_its_route(self):
        errors = self._errors(FIXTURES + "PlainOverrideViewset")

        self.assertEqual([e.id for e in errors], ["oidc.E002"])
        self.assertIn("login", errors[0].msg)

    def test_re_declaring_the_decorator_is_the_fix(self):
        self.assertEqual(self._errors(FIXTURES + "RedeclaredOverrideViewset"), [])

    def test_dropping_the_view_kwargs_is_caught(self):
        """The route matches on path, name and verbs, so only comparing the
        view kwargs catches this one."""
        errors = self._errors(FIXTURES + "DroppedViewKwargsViewset")

        self.assertEqual([e.id for e in errors], ["oidc.E002"])
        self.assertIn("session", errors[0].msg)

    def test_adding_to_the_view_kwargs_is_allowed(self):
        self.assertEqual(self._errors(FIXTURES + "WidenedViewKwargsViewset"), [])

    def tearDown(self):
        # The module was popped to force re-resolution; leave the registry as
        # found so later tests importing oidc.urls get the real settings.
        sys.modules.pop("oidc.urls", None)
