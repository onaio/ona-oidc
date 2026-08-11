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

    def test_adding_a_renderer_is_allowed(self):
        self.assertEqual(self._errors(FIXTURES + "WidenedViewKwargsViewset"), [])

    def _flagged(self, fixture, action_name):
        errors = self._errors(FIXTURES + fixture)

        self.assertEqual([e.id for e in errors], ["oidc.E002"])
        self.assertIn(action_name, errors[0].msg)

    def test_adding_an_authentication_class_is_caught(self):
        self._flagged("AddedAuthenticationViewset", "session")

    def test_moving_the_path_is_caught(self):
        self._flagged("MovedPathViewset", "login")

    def test_turning_it_into_a_detail_route_is_caught(self):
        self._flagged("DetailRouteViewset", "login")

    def test_losing_a_verb_is_caught(self):
        self._flagged("LostVerbViewset", "callback")

    def test_the_project_base_with_a_permission_is_clean(self):
        self.assertEqual(self._errors(FIXTURES + "GatedViewset"), [])

    def test_and_composing_a_permission_is_allowed(self):
        self.assertEqual(self._errors(FIXTURES + "TightenedPermissionViewset"), [])

    def test_or_composing_a_permission_is_caught(self):
        self._flagged("LoosenedPermissionViewset", "profile")

    def test_re_declaring_a_composed_permission_is_clean(self):
        self.assertEqual(self._errors(FIXTURES + "RedeclaredComposedViewset"), [])

    def test_dropping_a_composed_permission_is_caught(self):
        self._flagged("DroppedComposedViewset", "profile")

    def tearDown(self):
        # The module was popped to force re-resolution; leave the registry as
        # found so later tests importing oidc.urls get the real settings.
        sys.modules.pop("oidc.urls", None)
