"""Tests for module oidc.stepup"""

import time
from unittest.mock import patch
from urllib.parse import parse_qs, urlparse

from django.core.cache import cache
from django.test import TestCase
from django.test.utils import override_settings

from oidc.stepup import (
    build_step_up_url,
    find_step_up_auth_server,
    redeem_step_up,
    render_step_up_popup,
    subject_binding,
    verify_assurance,
    verify_subject,
)

# Keycloak's shape: emits acr, driven by the realm's acr.loa.map.
KEYCLOAK = {
    "AUTHORIZATION_ENDPOINT": (
        "https://kc.example/realms/r/protocol/openid-connect/auth"
    ),
    "CLIENT_ID": "app",
    "CLIENT_SECRET": "secret",
    "JWKS_ENDPOINT": "https://kc.example/realms/r/protocol/openid-connect/certs",
    "TOKEN_ENDPOINT": "https://kc.example/realms/r/protocol/openid-connect/token",
    "SCOPE": "openid profile email",
    "REDIRECT_URI": "https://app.example/oidc/kc/callback",
    "USE_PKCE": True,
    "STEP_UP": {
        "CLAIM": "acr",
        "MATCH": "equals",
        "SATISFIED_BY": ["gold"],
        "MAX_AGE": 0,
        "MAX_AUTH_AGE_SECONDS": 300,
        "REQUIRE_AUTH_TIME": True,
        "SUBJECT_CLAIM": "email",
        "REDIRECT_URI": "https://app.example/stepup/callback",
    },
}

SERVERS = {"login-only": {**KEYCLOAK, "STEP_UP": {}}, "kc": KEYCLOAK}


@override_settings(OPENID_CONNECT_AUTH_SERVERS=SERVERS)
class TestBuildStepUpUrl(TestCase):
    def setUp(self):
        cache.clear()

    def test_it_demands_a_fresh_authentication(self):
        """Without max_age the provider answers from the existing session,
        returns the assurance claim, and prompts the user for nothing."""
        url, _ = build_step_up_url("kc")

        self.assertEqual(parse_qs(urlparse(url).query)["max_age"], ["0"])

    def test_it_asks_for_the_configured_level(self):
        url, _ = build_step_up_url("kc")

        self.assertEqual(parse_qs(urlparse(url).query)["acr_values"], ["gold"])

    def test_it_asks_for_the_servers_scope(self):
        """A bare ``openid`` drops the claim the subject check reads, and the
        step-up is then refused as unverifiable for every user."""
        url, _ = build_step_up_url("kc")

        self.assertEqual(
            parse_qs(urlparse(url).query)["scope"], ["openid profile email"]
        )

    def test_it_uses_the_step_up_callback_not_the_login_one(self):
        """The login callback establishes a session; a step-up must not
        re-establish one as a side effect of proving a factor."""
        url, _ = build_step_up_url("kc")

        self.assertEqual(
            parse_qs(urlparse(url).query)["redirect_uri"],
            ["https://app.example/stepup/callback"],
        )

    def test_it_sends_pkce(self):
        url, _ = build_step_up_url("kc")
        query = parse_qs(urlparse(url).query)

        self.assertIn("code_challenge", query)
        self.assertEqual(query["code_challenge_method"], ["S256"])

    def test_the_state_carries_the_callers_context(self):
        """The provider returns to a URL, not to the control the user
        clicked, so intent has to survive the round trip."""
        _, state = build_step_up_url("kc", context={"audience": "reveal-key"})

        claims, context, reason = _redeem_with({"acr": "gold"}, "kc", state)

        self.assertIsNone(reason)
        self.assertEqual(context["audience"], "reveal-key")

    def test_the_nonce_is_cached_so_the_token_can_be_verified(self):
        """verify_and_decode_id_token reads the nonce back from the cache for
        both flows; an uncached one fails a token that is otherwise good."""
        url, _ = build_step_up_url("kc")
        nonce = parse_qs(urlparse(url).query)["nonce"][0]

        self.assertEqual(
            cache.get(nonce), {"auth_server": "kc", "redirect_after": None}
        )

    def test_a_server_without_a_step_up_block_asks_for_no_level(self):
        url, _ = build_step_up_url("login-only")

        self.assertNotIn("acr_values", parse_qs(urlparse(url).query))


def _redeem_with(claims, auth_server, state):
    with patch(
        "oidc.stepup.OpenIDClient.retrieve_tokens_using_auth_code",
        return_value={"id_token": "t"},
    ), patch(
        "oidc.stepup.OpenIDClient.verify_and_decode_id_token", return_value=claims
    ):
        return redeem_step_up(auth_server, "code", state)


@override_settings(OPENID_CONNECT_AUTH_SERVERS=SERVERS)
class TestRedeemStepUp(TestCase):
    def setUp(self):
        cache.clear()

    def test_the_state_is_single_use(self):
        """An outstanding state is a live authorisation; spending it twice
        would let one prompt satisfy two actions."""
        _, state = build_step_up_url("kc")
        _redeem_with({"acr": "gold"}, "kc", state)

        claims, _, reason = _redeem_with({"acr": "gold"}, "kc", state)

        self.assertIsNone(claims)
        self.assertEqual(reason, "state_unknown")

    def test_the_exchange_reuses_the_authorize_requests_callback(self):
        """RFC 6749 4.1.3 requires the two to be identical. Sending the login
        callback here, after asking with the step-up one, is rejected."""
        _, state = build_step_up_url("kc")

        with patch(
            "oidc.stepup.OpenIDClient.retrieve_tokens_using_auth_code",
            return_value={"id_token": "t"},
        ) as exchange, patch(
            "oidc.stepup.OpenIDClient.verify_and_decode_id_token", return_value={}
        ):
            redeem_step_up("kc", "code", state)

        self.assertEqual(
            exchange.call_args.kwargs["redirect_uri"],
            "https://app.example/stepup/callback",
        )

    def test_a_login_state_cannot_be_redeemed_as_a_step_up(self):
        """The two flows keep separate namespaces; sharing one would let a
        login authorisation be spent as proof of a second factor."""
        from oidc.client import state_cache_key

        cache.set(state_cache_key("shared"), "verifier", 300)

        claims, _, reason = _redeem_with({"acr": "gold"}, "kc", "shared")

        self.assertIsNone(claims)
        self.assertEqual(reason, "state_unknown")


class TestVerifyAssurance(TestCase):
    def test_a_matching_level_with_a_fresh_auth_time_satisfies(self):
        satisfied, _ = verify_assurance(
            {"acr": "gold", "auth_time": time.time()}, KEYCLOAK["STEP_UP"]
        )

        self.assertTrue(satisfied)

    def test_an_absent_claim_never_satisfies(self):
        """The silent downgrade: a valid token for the right user carrying no
        assurance claim at all."""
        satisfied, reason = verify_assurance(
            {"auth_time": time.time()}, KEYCLOAK["STEP_UP"]
        )

        self.assertFalse(satisfied)
        self.assertEqual(reason, "claim_absent")

    def test_a_lower_level_does_not_satisfy(self):
        satisfied, reason = verify_assurance(
            {"acr": "silver", "auth_time": time.time()}, KEYCLOAK["STEP_UP"]
        )

        self.assertFalse(satisfied)
        self.assertEqual(reason, "claim_unmatched")

    def test_a_stale_authentication_does_not_satisfy(self):
        satisfied, reason = verify_assurance(
            {"acr": "gold", "auth_time": time.time() - 4000}, KEYCLOAK["STEP_UP"]
        )

        self.assertFalse(satisfied)
        self.assertEqual(reason, "auth_time_stale")

    def test_a_missing_auth_time_does_not_satisfy(self):
        satisfied, reason = verify_assurance({"acr": "gold"}, KEYCLOAK["STEP_UP"])

        self.assertFalse(satisfied)
        self.assertEqual(reason, "auth_time_absent")

    def test_wso2_answers_with_amr_as_executor_class_names(self):
        """Not RFC 8176 values -- which is why the claim and match mode are
        configuration rather than constants."""
        config = {
            "CLAIM": "amr",
            "MATCH": "contains",
            "SATISFIED_BY": ["TOTPAuthenticator"],
            "REQUIRE_AUTH_TIME": False,
        }

        stepped_up = {"amr": ["BasicAuthenticator", "TOTPAuthenticator"]}
        password_only = {"amr": ["IdentifierExecutor", "BasicAuthenticator"]}

        self.assertTrue(verify_assurance(stepped_up, config)[0])
        self.assertFalse(verify_assurance(password_only, config)[0])

    def test_azure_b2c_answers_with_tfp_as_a_user_flow_name(self):
        config = {
            "CLAIM": "tfp",
            "SATISFIED_BY": ["B2C_1_MFA"],
            "REQUIRE_AUTH_TIME": False,
        }

        self.assertTrue(verify_assurance({"tfp": "B2C_1_MFA"}, config)[0])
        self.assertFalse(verify_assurance({"tfp": "B2C_1_SignUpSignIn"}, config)[0])

    def test_an_unconfigured_claim_never_satisfies(self):
        """Otherwise a deployment that forgot to configure one would treat
        every token as proof."""
        satisfied, reason = verify_assurance({"acr": "gold"}, {})

        self.assertFalse(satisfied)
        self.assertEqual(reason, "claim_unconfigured")


class TestVerifySubject(TestCase):
    def test_somebody_else_does_not(self):
        """The state is bound to the session that started the flow, so without
        this, finishing it as a different account mints the proof for the
        person who started it."""
        satisfied, reason = verify_subject(
            {"email": "bo@example.org"}, "ana@example.org", KEYCLOAK["STEP_UP"]
        )

        self.assertFalse(satisfied)
        self.assertEqual(reason, "subject_mismatch")

    def test_a_matching_subject_satisfies_whatever_the_casing(self):
        """Providers are inconsistent about email casing, and a capital
        letter is not a different person."""
        satisfied, _ = verify_subject(
            {"email": "ANA@Example.ORG"}, "ana@example.org", KEYCLOAK["STEP_UP"]
        )

        self.assertTrue(satisfied)

    def test_an_absent_claim_fails_closed(self):
        """Nothing to disagree with is not agreement."""
        satisfied, reason = verify_subject({}, "ana@example.org", KEYCLOAK["STEP_UP"])

        self.assertFalse(satisfied)
        self.assertEqual(reason, "subject_unverifiable")

    def test_an_absent_expected_value_fails_closed(self):
        satisfied, reason = verify_subject(
            {"email": "ana@example.org"}, "", KEYCLOAK["STEP_UP"]
        )

        self.assertFalse(satisfied)
        self.assertEqual(reason, "subject_unverifiable")


@override_settings(OPENID_CONNECT_AUTH_SERVERS=SERVERS)
class TestFindStepUpAuthServer(TestCase):
    def test_it_picks_the_server_carrying_a_step_up_block(self):
        self.assertEqual(find_step_up_auth_server(), "kc")

    @override_settings(OPENID_CONNECT_AUTH_SERVERS={"a": {"CLIENT_ID": "x"}})
    def test_it_reports_none_when_no_server_is_configured_for_step_up(self):
        self.assertIsNone(find_step_up_auth_server())


class TestSubjectBinding(TestCase):
    """Step-up must identify people the same way login does."""

    def test_it_defaults_to_the_claim_login_identifies_users_by(self):
        # USER_UNIQUE_FILTER_FIELDS starts with "username", which
        # MAP_CLAIM_TO_MODEL reaches from "preferred_username".
        self.assertEqual(subject_binding({}), ("preferred_username", "username"))

    @override_settings(
        OPENID_CONNECT_VIEWSET_CONFIG={"USER_UNIQUE_FILTER_FIELDS": ["email"]}
    )
    def test_it_follows_a_deployment_that_identifies_users_by_email(self):
        self.assertEqual(subject_binding({}), ("email", "email"))

    def test_an_explicit_claim_still_wins(self):
        """For providers whose step-up token carries a different claim than
        their login token."""
        binding = subject_binding({"SUBJECT_CLAIM": "sub", "SUBJECT_FIELD": "id"})

        self.assertEqual(binding, ("sub", "id"))

    def test_verify_subject_reads_the_defaulted_claim(self):
        satisfied, _ = verify_subject({"preferred_username": "ana"}, "ana", {})

        self.assertTrue(satisfied)


from oidc.checks import check_step_up_demands_fresh_authentication  # noqa: E402


class TestFreshAuthenticationCheck(TestCase):
    @override_settings(OPENID_CONNECT_AUTH_SERVERS=SERVERS)
    def test_a_zero_max_age_is_silent(self):
        self.assertEqual(check_step_up_demands_fresh_authentication(), [])

    @override_settings(
        OPENID_CONNECT_AUTH_SERVERS={"kc": {"STEP_UP": {"MAX_AGE": 600}}}
    )
    def test_a_non_zero_max_age_is_reported(self):
        """Without max_age=0 an already stepped-up session answers from the
        cookie and returns the claim having prompted for nothing."""
        warnings = check_step_up_demands_fresh_authentication()

        self.assertEqual([w.id for w in warnings], ["oidc.W001"])


class TestPopupRendering(TestCase):
    def test_it_never_posts_to_a_wildcard_origin(self):
        """The result is a credential for the gated action; a permissive
        target hands it to any page listening."""
        html = render_step_up_popup("https://app.example", grant="g-1")

        self.assertIn('"https://app.example"', html)
        self.assertNotIn('"*"', html)
        self.assertIn("g-1", html)

    def test_it_reports_a_failure_without_a_grant(self):
        html = render_step_up_popup("https://app.example", reason="claim_absent")

        self.assertIn("claim_absent", html)

    def test_a_verified_step_up_with_no_grant_is_not_a_failure(self):
        """The mixin allows applications that set a flag or write an audit
        record instead of minting a grant, so a verified step-up with no grant
        must read as success, not error."""
        html = render_step_up_popup("https://app.example", grant=None, reason=None)

        self.assertIn("verified", html)
        self.assertNotIn("error", html)

    def test_an_unset_origin_renders_nothing(self):
        """postMessage(data, "") throws inside a popup, where nobody sees it.
        Empty lets the caller refuse loudly instead."""
        self.assertEqual(render_step_up_popup("", grant="g-1"), "")

    def test_it_cannot_be_broken_out_of(self):
        """The payload is a JavaScript value, and an unescaped </script> in it
        would end the block early."""
        html = render_step_up_popup("https://app.example", reason="</script>x")

        self.assertNotIn("</script>x", html)
        self.assertEqual(html.count("</script>"), 1)


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

            def expected_subject(self, request, claims):
                return "ana@example.org"

        return View()

    def _complete(self, view, claims, state):
        with patch(
            "oidc.stepup.OpenIDClient.retrieve_tokens_using_auth_code",
            return_value={"id_token": "t"},
        ), patch(
            "oidc.stepup.OpenIDClient.verify_and_decode_id_token", return_value=claims
        ):
            # expected_subject and verify_step_up_context are both overridden
            # above, so the request itself is never read.
            return view.complete_step_up(None, "code", state, "kc")

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


@override_settings(OPENID_CONNECT_AUTH_SERVERS=SERVERS)
class TestProviderMisbehaviour(TestCase):
    """What the module exists for: providers that answer in unexpected shapes --
    a shape that crashes or matches by accident reaches the user as a traceback
    rather than a refusal.
    """

    def setUp(self):
        cache.clear()

    def test_an_exchange_failure_is_a_refusal_not_a_traceback(self):
        """A provider that is down, a rejected code, or a nonce that does not
        verify are all refusals from the caller's point of view."""
        _, state = build_step_up_url("kc")

        with patch(
            "oidc.stepup.OpenIDClient.retrieve_tokens_using_auth_code",
            side_effect=RuntimeError("upstream is down"),
        ):
            claims, _, reason = redeem_step_up("kc", "code", state)

        self.assertIsNone(claims)
        self.assertEqual(reason, "exchange_failed")

    def test_a_string_under_a_contains_match_is_not_split_into_characters(self):
        """set("gold") is {"g","o","l","d"}, which can intersect a
        single-character accepted value by accident."""
        config = {
            "CLAIM": "amr",
            "MATCH": "contains",
            "SATISFIED_BY": ["g"],
            "REQUIRE_AUTH_TIME": False,
        }

        self.assertFalse(verify_assurance({"amr": "gold"}, config)[0])

    def test_a_string_under_a_contains_match_still_matches_itself(self):
        config = {
            "CLAIM": "amr",
            "MATCH": "contains",
            "SATISFIED_BY": ["gold"],
            "REQUIRE_AUTH_TIME": False,
        }

        self.assertTrue(verify_assurance({"amr": "gold"}, config)[0])

    def test_a_list_under_an_equals_match_does_not_raise(self):
        """`value in accepted` on a list raises TypeError: unhashable."""
        config = {"CLAIM": "acr", "SATISFIED_BY": ["gold"], "REQUIRE_AUTH_TIME": False}

        self.assertTrue(verify_assurance({"acr": ["gold"]}, config)[0])
        self.assertFalse(verify_assurance({"acr": ["silver"]}, config)[0])

    @override_settings(OPENID_CONNECT_AUTH_SERVERS={"broken": {"CLIENT_ID": "x"}})
    def test_a_server_with_no_authorization_endpoint_fails_loudly(self):
        """Otherwise the browser is sent to "None?client_id=..."."""
        with self.assertRaises(ValueError):
            build_step_up_url("broken")
