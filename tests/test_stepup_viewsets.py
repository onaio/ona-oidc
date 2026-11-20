"""Tests for module oidc.stepup_viewsets"""

import time
from types import SimpleNamespace
from unittest.mock import patch

from django.core.cache import cache
from django.test import TestCase
from django.test.utils import override_settings

from oidc.stepup import build_step_up_url
from tests.error_reports import escaped_frames, reported_locals
from tests.test_stepup import BY_USERNAME, KEYCLOAK, SERVERS, flow_nonce


@override_settings(OPENID_CONNECT_AUTH_SERVERS=SERVERS)
class TestStepUpCallbackMixin(TestCase):
    """Each case proves one wire is connected, and short-circuits on failure.

    The verifiers themselves are covered above; what is asserted here is that
    the mixin calls them, in the right order, and does not reach the
    application when one refuses.
    """

    def setUp(self):
        cache.clear()

    def _view(self, context_reason=None):
        from oidc.stepup_viewsets import StepUpCallbackMixin

        class View(StepUpCallbackMixin):
            def verify_step_up_context(self, request, context):
                return context_reason

            def on_step_up_verified(self, request, claims, context):
                return f"granted:{context.get('audience')}"

        return View()

    def _complete(self, view, claims, state, auth_server="kc"):
        # verify_step_up_context is overridden above, so the request is read
        # only for its user.
        request = SimpleNamespace(
            user=SimpleNamespace(email="ana@example.org", username="ana")
        )
        with (
            patch(
                "oidc.stepup.OpenIDClient.retrieve_tokens_using_auth_code",
                return_value={"id_token": "t"},
            ),
            patch(
                "oidc.stepup.OpenIDClient.verify_and_decode_id_token",
                return_value={"nonce": flow_nonce(state), **claims},
            ),
        ):
            return view.complete_step_up(request, "code", state, auth_server)

    @staticmethod
    def _fresh(**claims):
        return {"auth_time": time.time(), **claims}

    def test_a_satisfying_token_reaches_the_application(self):
        _, state = build_step_up_url("kc", context={"audience": "reveal"})
        result, reason = self._complete(
            self._view(), self._fresh(acr="gold", email="ana@example.org"), state
        )

        self.assertIsNone(reason)
        self.assertEqual(result, "granted:reveal")

    def test_an_unbound_state_is_refused_by_default(self):
        """An application that never binds the state to its caller would let
        one user complete a flow, and the action its context carries, that
        another user started."""
        from oidc.stepup_viewsets import StepUpCallbackMixin

        class View(StepUpCallbackMixin):
            def on_step_up_verified(self, request, claims, context):
                return "granted"

        _, state = build_step_up_url("kc", context={"audience": "reveal"})
        result, reason = self._complete(
            View(), self._fresh(acr="gold", email="ana@example.org"), state
        )

        self.assertIsNone(result)
        self.assertEqual(reason, "state_unbound")

    def test_the_application_checks_its_own_state_first(self):
        """Before the token is examined, so a state belonging to someone else
        is reported as that rather than as a subject mismatch."""
        _, state = build_step_up_url("kc", context={"audience": "reveal"})
        result, reason = self._complete(
            self._view(context_reason="state_user_mismatch"),
            self._fresh(acr="gold", email="somebody@else.org"),
            state,
        )

        self.assertIsNone(result)
        self.assertEqual(reason, "state_user_mismatch")

    def test_a_token_for_somebody_else_never_reaches_the_application(self):
        _, state = build_step_up_url("kc", context={"audience": "reveal"})
        result, reason = self._complete(
            self._view(), self._fresh(acr="gold", email="bo@example.org"), state
        )

        self.assertIsNone(result)
        self.assertEqual(reason, "subject_mismatch")

    def test_a_weak_token_never_reaches_the_application(self):
        _, state = build_step_up_url("kc", context={"audience": "reveal"})
        result, reason = self._complete(
            self._view(), self._fresh(acr="silver", email="ana@example.org"), state
        )

        self.assertIsNone(result)
        self.assertEqual(reason, "claim_unmatched")

    @override_settings(
        OPENID_CONNECT_AUTH_SERVERS={"kc": {**KEYCLOAK, "CHECK_EMAIL_VERIFIED": True}}
    )
    def test_an_unverified_email_is_refused_where_login_checks_it(self):
        """Otherwise an identity holding the user's address unverified, with
        its own factor, earns the user's grant."""
        _, state = build_step_up_url("kc", context={"audience": "reveal"})
        result, reason = self._complete(
            self._view(),
            self._fresh(acr="gold", email="ana@example.org", email_verified=False),
            state,
        )

        self.assertIsNone(result)
        self.assertEqual(reason, "email_unverified")

    @override_settings(
        OPENID_CONNECT_AUTH_SERVERS={"kc": {**KEYCLOAK, "CHECK_EMAIL_VERIFIED": True}}
    )
    def test_a_verified_email_passes_where_login_checks_it(self):
        _, state = build_step_up_url("kc", context={"audience": "reveal"})
        result, reason = self._complete(
            self._view(),
            self._fresh(acr="gold", email="ana@example.org", email_verified=" True "),
            state,
        )

        self.assertIsNone(reason)
        self.assertEqual(result, "granted:reveal")

    def test_an_unverified_email_passes_where_login_does_not_check_it(self):
        _, state = build_step_up_url("kc", context={"audience": "reveal"})
        result, reason = self._complete(
            self._view(),
            self._fresh(acr="gold", email="ana@example.org", email_verified=False),
            state,
        )

        self.assertIsNone(reason)
        self.assertEqual(result, "granted:reveal")

    @override_settings(
        OPENID_CONNECT_AUTH_SERVERS={"kc": {**KEYCLOAK, "REQUIRE_VERIFIED_EMAIL": True}}
    )
    def test_a_missing_email_verified_claim_is_refused_where_required(self):
        _, state = build_step_up_url("kc", context={"audience": "reveal"})
        result, reason = self._complete(
            self._view(), self._fresh(acr="gold", email="ana@example.org"), state
        )

        self.assertIsNone(result)
        self.assertEqual(reason, "email_unverified")

    @override_settings(
        OPENID_CONNECT_AUTH_SERVERS={
            "kc": {
                **KEYCLOAK,
                "CHECK_EMAIL_VERIFIED": True,
                "STEP_UP": {
                    **KEYCLOAK["STEP_UP"],
                    "SUBJECT_CLAIM": "upn",
                    "SUBJECT_FIELD": "email",
                },
            }
        }
    )
    def test_a_claim_mapped_onto_the_email_field_ignores_the_email_flag(self):
        """``email_verified`` describes the ``email`` claim, not ``upn``."""
        _, state = build_step_up_url("kc", context={"audience": "reveal"})
        result, reason = self._complete(
            self._view(),
            self._fresh(acr="gold", upn="ana@example.org", email_verified=False),
            state,
        )

        self.assertIsNone(reason)
        self.assertEqual(result, "granted:reveal")

    @override_settings(
        OPENID_CONNECT_AUTH_SERVERS={**SERVERS, "by-username": BY_USERNAME}
    )
    def test_the_subject_is_read_with_the_completing_servers_binding(self):
        """Not the first step-up server's: "kc" binds by email, so reading
        its binding here would compare the user's email to a username."""
        _, state = build_step_up_url("by-username", context={"audience": "reveal"})
        result, reason = self._complete(
            self._view(),
            self._fresh(acr="gold", preferred_username="ana"),
            state,
            auth_server="by-username",
        )

        self.assertIsNone(reason)
        self.assertEqual(result, "granted:reveal")

    @override_settings(STEP_UP_POPUP_ORIGIN="https://app.example")
    def test_the_popup_keeps_its_opener_and_is_not_stored(self):
        """Django's default Cross-Origin-Opener-Policy, same-origin, would
        null ``window.opener`` and the result would never reach the caller."""
        view = self._view()
        view.request = SimpleNamespace(csp_nonce="n-2")
        response = view.step_up_popup_response("g-1")

        self.assertEqual(response.status_code, 200)
        self.assertIn('nonce="n-2"', response.content.decode())
        self.assertEqual(response["Cross-Origin-Opener-Policy"], "unsafe-none")
        self.assertEqual(response["Cache-Control"], "no-store")

    @override_settings(OPENID_CONNECT_AUTH_SERVERS={"kc": KEYCLOAK, "kc2": KEYCLOAK})
    def test_an_unnamed_server_is_read_from_the_state(self):
        """With two step-up servers, defaulting to the first would refuse
        every flow started against the second after the user proved a
        factor."""
        _, state = build_step_up_url("kc2", context={"audience": "reveal"})
        result, reason = self._complete(
            self._view(),
            self._fresh(acr="gold", email="ana@example.org"),
            state,
            auth_server=None,
        )

        self.assertIsNone(reason)
        self.assertEqual(result, "granted:reveal")

    @override_settings(OPENID_CONNECT_AUTH_SERVERS={"login-only": {"STEP_UP": {}}})
    def test_no_step_up_server_is_reported_as_unavailable(self):
        result, reason = self._complete(
            self._view(), self._fresh(), "unknown-state", auth_server=None
        )

        self.assertIsNone(result)
        self.assertEqual(reason, "step_up_unavailable")

    @override_settings(STEP_UP_POPUP_ORIGIN="")
    def test_an_unset_popup_origin_is_a_server_error(self):
        response = self._view().step_up_popup_response("g-1")

        self.assertEqual(response.status_code, 500)
        self.assertNotIn("g-1", response.content.decode())
        self.assertEqual(response["Cache-Control"], "no-store")

    def test_an_error_report_leaves_out_the_code_state_and_claims(self):
        """An application error after verification would otherwise put the
        authorization code, the state and the token's claims in the report."""
        from oidc.stepup_viewsets import StepUpCallbackMixin

        class View(StepUpCallbackMixin):
            def verify_step_up_context(self, request, context):
                return None

            def on_step_up_verified(self, request, claims, context):
                raise RuntimeError("application failure")

        _, state = build_step_up_url("kc", context={"audience": "reveal"})
        frames = escaped_frames(
            lambda: self._complete(
                View(), self._fresh(acr="gold", email="ana@example.org"), state
            ),
            RuntimeError,
            "complete_step_up",
        )

        self.assertEqual(frames[0].f_locals.get("state"), state)
        reported = str(reported_locals(frames[0]))
        for value in (state, "ana@example.org"):
            self.assertNotIn(value, reported)
