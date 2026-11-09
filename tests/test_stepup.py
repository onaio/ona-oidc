"""Tests for module oidc.stepup"""

import json
import time
from types import SimpleNamespace
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
    subject_binding_is_safe,
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
        "SATISFIED_BY": ["gold"],
        "MAX_AGE": 0,
        "MAX_AUTH_AGE_SECONDS": 300,
        "REQUIRE_AUTH_TIME": True,
        "SUBJECT_CLAIM": "email",
        "REDIRECT_URI": "https://app.example/stepup/callback",
    },
}

SERVERS = {"login-only": {**KEYCLOAK, "STEP_UP": {}}, "kc": KEYCLOAK}

# A second step-up server that identifies people by username, not email.
BY_USERNAME = {
    **KEYCLOAK,
    "STEP_UP": {**KEYCLOAK["STEP_UP"], "SUBJECT_CLAIM": "preferred_username"},
}


@override_settings(OPENID_CONNECT_AUTH_SERVERS=SERVERS)
class TestBuildStepUpUrl(TestCase):
    def setUp(self):
        cache.clear()

    def test_it_demands_a_fresh_authentication(self):
        """Without max_age the provider answers from the existing session,
        returns the assurance claim, and prompts the user for nothing."""
        url, _ = build_step_up_url("kc")

        self.assertEqual(parse_qs(urlparse(url).query)["max_age"], ["0"])

    def test_it_asks_for_auth_time(self):
        """WSO2 Identity Server re-prompts on max_age=0 but treats 0 as "not
        sent" when building the ID token, so auth_time is left out and the
        freshness check refuses every step-up."""
        url, _ = build_step_up_url("kc")

        claims = parse_qs(urlparse(url).query)["claims"]
        self.assertEqual(
            json.loads(claims[0]), {"id_token": {"auth_time": {"essential": True}}}
        )

    @override_settings(
        OPENID_CONNECT_AUTH_SERVERS={
            "kc": {**KEYCLOAK, "STEP_UP": {**KEYCLOAK["STEP_UP"], "PROMPT": "login"}}
        }
    )
    def test_it_sends_a_configured_prompt(self):
        """Azure AD B2C documents prompt=login, not max_age, as the way to
        make the user sign in again instead of reusing the session."""
        url, _ = build_step_up_url("kc")

        self.assertEqual(parse_qs(urlparse(url).query)["prompt"], ["login"])

    def test_it_sends_no_prompt_unless_configured(self):
        url, _ = build_step_up_url("kc")

        self.assertNotIn("prompt", parse_qs(urlparse(url).query))

    def test_it_asks_for_the_configured_level(self):
        url, _ = build_step_up_url("kc")

        self.assertEqual(parse_qs(urlparse(url).query)["acr_values"], ["gold"])

    @override_settings(
        OPENID_CONNECT_AUTH_SERVERS={
            "kc": {**KEYCLOAK, "STEP_UP": {**KEYCLOAK["STEP_UP"], "SATISFIED_BY": [2]}}
        }
    )
    def test_a_numeric_level_is_asked_for_as_text(self):
        url, _ = build_step_up_url("kc")

        self.assertEqual(parse_qs(urlparse(url).query)["acr_values"], ["2"])

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

    @override_settings(
        OPENID_CONNECT_AUTH_SERVERS={
            "callback-only": {
                **KEYCLOAK,
                "STEP_UP": {"REDIRECT_URI": "https://app.example/stepup/callback"},
            }
        }
    )
    def test_a_server_without_a_required_level_asks_for_none(self):
        url, _ = build_step_up_url("callback-only")

        self.assertNotIn("acr_values", parse_qs(urlparse(url).query))

    def test_a_missing_step_up_callback_fails_loudly(self):
        """Falling back to the login callback would strand every step-up
        there: it looks the state up in the login namespace and refuses."""
        with self.assertRaises(ValueError):
            build_step_up_url("login-only")


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
        _, _, first_reason = _redeem_with({"acr": "gold"}, "kc", state)
        self.assertIsNone(first_reason)

        claims, _, reason = _redeem_with({"acr": "gold"}, "kc", state)

        self.assertIsNone(claims)
        self.assertEqual(reason, "state_unknown")

    def test_redemption_binds_to_the_state_s_auth_server(self):
        """The callback names the server, but the state decides it: a flow
        started for one server must not be redeemed with another's client."""
        _, state = build_step_up_url("kc")

        claims, _, reason = _redeem_with({"acr": "gold"}, "login-only", state)

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

    def test_an_authentication_from_before_the_flow_began_is_refused(self):
        """A provider that ignores max_age=0 answers from the session and
        returns the login's auth_time. Recent enough for MAX_AUTH_AGE_SECONDS,
        but not a factor proved for this request."""
        _, state = build_step_up_url("kc")

        claims, _, reason = _redeem_with(
            {"acr": "gold", "auth_time": time.time() - 120}, "kc", state
        )

        self.assertIsNone(claims)
        self.assertEqual(reason, "auth_time_stale")

    def test_an_authentication_during_the_flow_is_accepted(self):
        _, state = build_step_up_url("kc")

        claims, _, reason = _redeem_with(
            {"acr": "gold", "auth_time": time.time()}, "kc", state
        )

        self.assertIsNone(reason)
        self.assertEqual(claims["acr"], "gold")

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

    def test_an_auth_time_in_the_future_does_not_satisfy(self):
        satisfied, reason = verify_assurance(
            {"acr": "gold", "auth_time": time.time() + 600}, KEYCLOAK["STEP_UP"]
        )

        self.assertFalse(satisfied)
        self.assertEqual(reason, "auth_time_stale")

    def test_a_non_finite_auth_time_does_not_satisfy(self):
        """NaN compares false both ways, so it would pass every age check."""
        satisfied, reason = verify_assurance(
            {"acr": "gold", "auth_time": float("nan")}, KEYCLOAK["STEP_UP"]
        )

        self.assertFalse(satisfied)
        self.assertEqual(reason, "auth_time_absent")

    def test_a_missing_auth_time_does_not_satisfy(self):
        satisfied, reason = verify_assurance({"acr": "gold"}, KEYCLOAK["STEP_UP"])

        self.assertFalse(satisfied)
        self.assertEqual(reason, "auth_time_absent")

    def test_wso2_answers_with_amr_as_executor_class_names(self):
        """Not RFC 8176 values, which is why the claim is configuration
        rather than a constant."""
        config = {
            "CLAIM": "amr",
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

    def test_it_defaults_to_the_email_login_resolves_accounts_by(self):
        """Not the username: the default USER_UNIQUE_FILTER_FIELDS starts with
        it, but login never looks a user up by it."""
        self.assertEqual(subject_binding({}), ("email", "email"))

    @override_settings(
        OPENID_CONNECT_VIEWSET_CONFIG={"MAP_CLAIM_TO_MODEL": {"upn": "email"}}
    )
    def test_a_deployment_that_remaps_email_is_followed(self):
        """Login fills the email field from ``upn`` here, so the raw
        ``email`` claim is not what it trusts."""
        self.assertEqual(subject_binding({}), ("upn", "email"))

    def test_an_email_claim_alone_binds_the_email_field(self):
        self.assertEqual(
            subject_binding({"SUBJECT_CLAIM": "email"}), ("email", "email")
        )

    def test_an_emails_claim_alone_binds_the_email_field(self):
        binding = subject_binding({"SUBJECT_CLAIM": "emails"})

        self.assertEqual(binding, ("emails", "email"))

    def test_a_claim_alone_is_paired_with_its_mapped_field(self):
        binding = subject_binding({"SUBJECT_CLAIM": "preferred_username"})

        self.assertEqual(binding, ("preferred_username", "username"))

    def test_a_field_alone_is_paired_with_its_mapped_claim(self):
        binding = subject_binding({"SUBJECT_FIELD": "username"})

        self.assertEqual(binding, ("preferred_username", "username"))

    def test_an_explicit_claim_still_wins(self):
        """For providers whose step-up token carries a different claim than
        their login token."""
        binding = subject_binding({"SUBJECT_CLAIM": "sub", "SUBJECT_FIELD": "id"})

        self.assertEqual(binding, ("sub", "id"))

    def test_verify_subject_reads_the_defaulted_claim(self):
        claims = {"email": "ana@example.org", "preferred_username": "bo"}

        self.assertTrue(verify_subject(claims, "ana@example.org", {})[0])
        self.assertFalse(verify_subject(claims, "bo", {})[0])


class TestSubjectBindingIsSafe(TestCase):
    """Only an email binding is safe without the application gating the field
    against change."""

    def test_the_default_binding_is_safe(self):
        self.assertTrue(subject_binding_is_safe({}))

    def test_an_email_claim_is_safe(self):
        self.assertTrue(subject_binding_is_safe({"SUBJECT_CLAIM": "email"}))

    @override_settings(
        OPENID_CONNECT_VIEWSET_CONFIG={"MAP_CLAIM_TO_MODEL": {"upn": "email"}}
    )
    def test_a_claim_remapped_onto_the_email_field_is_safe(self):
        self.assertTrue(subject_binding_is_safe({"SUBJECT_CLAIM": "upn"}))

    def test_a_username_field_is_not_safe(self):
        self.assertFalse(subject_binding_is_safe({"SUBJECT_FIELD": "username"}))

    def test_a_username_claim_is_not_safe(self):
        self.assertFalse(
            subject_binding_is_safe({"SUBJECT_CLAIM": "preferred_username"})
        )

    def test_the_default_falls_back_to_the_emails_list(self):
        claims = {"emails": ["ana@example.org"]}

        self.assertTrue(verify_subject(claims, "ana@example.org", {})[0])

    def test_a_list_valued_claim_matches_any_member(self):
        """Azure AD B2C sends ``emails``, a list."""
        config = {"SUBJECT_CLAIM": "emails", "SUBJECT_FIELD": "email"}
        claims = {"emails": ["old@example.org", "ana@example.org"]}

        self.assertTrue(verify_subject(claims, "ana@example.org", config)[0])
        self.assertFalse(verify_subject(claims, "bo@example.org", config)[0])


from oidc.checks import (  # noqa: E402
    check_step_up_demands_fresh_authentication,
    check_step_up_grants_use_a_shared_cache,
)

_LOCMEM = {"default": {"BACKEND": "django.core.cache.backends.locmem.LocMemCache"}}
_REDIS = {"default": {"BACKEND": "django_redis.cache.RedisCache"}}


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


class TestGrantCacheCheck(TestCase):
    @override_settings(OPENID_CONNECT_AUTH_SERVERS=SERVERS, CACHES=_LOCMEM)
    def test_local_memory_with_step_up_is_reported(self):
        warnings = check_step_up_grants_use_a_shared_cache()

        self.assertEqual([w.id for w in warnings], ["oidc.W002"])

    @override_settings(OPENID_CONNECT_AUTH_SERVERS=SERVERS, CACHES=_REDIS)
    def test_a_shared_cache_is_silent(self):
        self.assertEqual(check_step_up_grants_use_a_shared_cache(), [])

    @override_settings(
        OPENID_CONNECT_AUTH_SERVERS={"login-only": {"STEP_UP": {}}}, CACHES=_LOCMEM
    )
    def test_no_step_up_server_means_the_cache_is_irrelevant(self):
        self.assertEqual(check_step_up_grants_use_a_shared_cache(), [])


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

    def test_the_script_carries_the_csp_nonce(self):
        html = render_step_up_popup("https://app.example", grant="g", nonce="n-1")

        self.assertIn('<script nonce="n-1">', html)

    def test_a_wildcard_origin_renders_nothing(self):
        self.assertEqual(render_step_up_popup("*", grant="g-1"), "")

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

        return View()

    def _complete(self, view, claims, state, auth_server="kc"):
        # verify_step_up_context is overridden above, so the request is read
        # only for its user.
        request = SimpleNamespace(
            user=SimpleNamespace(email="ana@example.org", username="ana")
        )
        with patch(
            "oidc.stepup.OpenIDClient.retrieve_tokens_using_auth_code",
            return_value={"id_token": "t"},
        ), patch(
            "oidc.stepup.OpenIDClient.verify_and_decode_id_token", return_value=claims
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


@override_settings(OPENID_CONNECT_AUTH_SERVERS=SERVERS)
class TestProviderMisbehaviour(TestCase):
    """Providers that answer in unexpected shapes. A shape that crashes
    reaches the user as a traceback, and one that matches by accident passes
    a step-up that should fail.
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

    def test_a_string_claim_is_not_split_into_characters(self):
        """set("gold") is {"g","o","l","d"}, which can intersect a
        single-character accepted value by accident."""
        config = {
            "CLAIM": "amr",
            "SATISFIED_BY": ["g"],
            "REQUIRE_AUTH_TIME": False,
        }

        self.assertFalse(verify_assurance({"amr": "gold"}, config)[0])

    def test_a_numeric_level_matches_as_configured(self):
        config = {"CLAIM": "loa", "SATISFIED_BY": [2], "REQUIRE_AUTH_TIME": False}

        self.assertTrue(verify_assurance({"loa": 2}, config)[0])

    def test_a_numeric_level_matches_the_text_the_provider_sends(self):
        """acr_values carries the level as text and OIDC Core defines acr as
        a string, so a level configured as 2 comes back as "2"."""
        config = {"CLAIM": "acr", "SATISFIED_BY": [2], "REQUIRE_AUTH_TIME": False}

        self.assertTrue(verify_assurance({"acr": "2"}, config)[0])

    def test_a_textual_level_matches_a_numeric_claim(self):
        config = {"CLAIM": "loa", "SATISFIED_BY": ["2"], "REQUIRE_AUTH_TIME": False}

        self.assertTrue(verify_assurance({"loa": 2}, config)[0])

    def test_a_boolean_claim_is_not_a_level(self):
        """Python treats True as 1, and str(True) is "True": neither may let a
        boolean satisfy a level."""
        config = {
            "CLAIM": "loa",
            "SATISFIED_BY": [1, "True"],
            "REQUIRE_AUTH_TIME": False,
        }

        self.assertEqual(
            verify_assurance({"loa": True}, config), (False, "claim_unmatched")
        )

    def test_an_unmatched_mixed_type_level_is_refused_not_raised(self):
        """Logging the accepted values must not sort ints against strings."""
        config = {
            "CLAIM": "acr",
            "SATISFIED_BY": [2, "gold"],
            "REQUIRE_AUTH_TIME": False,
        }

        self.assertEqual(
            verify_assurance({"acr": "silver"}, config), (False, "claim_unmatched")
        )

    def test_a_string_satisfied_by_is_refused_not_split(self):
        """As a string, "10" would accept a level-1 token."""
        config = {"CLAIM": "acr", "SATISFIED_BY": "10", "REQUIRE_AUTH_TIME": False}

        self.assertEqual(
            verify_assurance({"acr": "1"}, config), (False, "claim_unconfigured")
        )

    @override_settings(OPENID_CONNECT_AUTH_SERVERS={"broken": {"CLIENT_ID": "x"}})
    def test_a_server_with_no_authorization_endpoint_fails_loudly(self):
        """Otherwise the browser is sent to "None?client_id=..."."""
        with self.assertRaises(ValueError):
            build_step_up_url("broken")
