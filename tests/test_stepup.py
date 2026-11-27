"""Tests for module oidc.stepup"""

import json
import time
from unittest.mock import patch
from urllib.parse import parse_qs, urlparse

from django.core.cache import cache
from django.test import TestCase
from django.test.utils import override_settings

from oidc.client import OpenIDClient
from oidc.stepup import (
    _step_up_state_key,
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

    @override_settings(
        OPENID_CONNECT_AUTH_SERVERS={
            "kc": {**KEYCLOAK, "PKCE_CODE_CHALLENGE_METHOD": "plain"}
        }
    )
    def test_the_challenge_method_names_the_s256_challenge_it_sends(self):
        """The challenge is always a SHA-256 digest. Naming the login's method
        instead would have the provider compare the verifier to it as plain
        text and reject the exchange."""
        url, _ = build_step_up_url("kc")

        self.assertEqual(
            parse_qs(urlparse(url).query)["code_challenge_method"], ["S256"]
        )

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
                "STEP_UP": {
                    **KEYCLOAK["STEP_UP"],
                    "CLAIM": "amr",
                    "SATISFIED_BY": ["totp"],
                },
            }
        }
    )
    def test_a_server_read_through_amr_asks_for_no_acr_level(self):
        """acr_values names acr levels. A provider read through amr would be
        asked for an acr called "totp"."""
        url, _ = build_step_up_url("callback-only")

        self.assertNotIn("acr_values", parse_qs(urlparse(url).query))

    def test_a_missing_step_up_callback_fails_loudly(self):
        """Falling back to the login callback would strand every step-up
        there: it looks the state up in the login namespace and refuses."""
        with self.assertRaises(ValueError):
            build_step_up_url("login-only")


def flow_nonce(state):
    """The nonce the step-up started as ``state`` sent, as a provider echoes it."""
    return (cache.get(_step_up_state_key(state)) or {}).get("nonce")


def _redeem_with(claims, auth_server, state, echo_nonce=True):
    if echo_nonce:
        claims = {"nonce": flow_nonce(state), **claims}
    with (
        patch(
            "oidc.stepup.OpenIDClient.retrieve_tokens_using_auth_code",
            return_value={"id_token": "t"},
        ),
        patch(
            "oidc.stepup.OpenIDClient.verify_and_decode_id_token", return_value=claims
        ),
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

    def test_the_exchange_sends_the_verifier_for_the_url_s_challenge(self):
        """The exchange is mocked everywhere else, so a verifier from another
        flow would pass every test and fail against a real provider."""
        url, state = build_step_up_url("kc")
        challenge = parse_qs(urlparse(url).query)["code_challenge"][0]

        with (
            patch(
                "oidc.stepup.OpenIDClient.retrieve_tokens_using_auth_code",
                return_value={"id_token": "t"},
            ) as exchange,
            patch(
                "oidc.stepup.OpenIDClient.verify_and_decode_id_token",
                return_value={"acr": "gold"},
            ),
        ):
            redeem_step_up("kc", "code", state)

        verifier = exchange.call_args.kwargs["code_verifier"]
        self.assertEqual(
            OpenIDClient("kc").generate_pkce_code_challenge(verifier), challenge
        )

    def test_the_exchange_reuses_the_authorize_requests_callback(self):
        """RFC 6749 4.1.3 requires the two to be identical. Sending the login
        callback here, after asking with the step-up one, is rejected."""
        _, state = build_step_up_url("kc")

        with (
            patch(
                "oidc.stepup.OpenIDClient.retrieve_tokens_using_auth_code",
                return_value={"id_token": "t"},
            ) as exchange,
            patch(
                "oidc.stepup.OpenIDClient.verify_and_decode_id_token", return_value={}
            ),
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

    def test_the_nonce_this_flow_sent_is_accepted(self):
        url, state = build_step_up_url("kc")
        sent = parse_qs(urlparse(url).query)["nonce"][0]

        claims, _, reason = _redeem_with(
            {"acr": "gold", "nonce": sent}, "kc", state, echo_nonce=False
        )

        self.assertIsNone(reason)
        self.assertEqual(claims["acr"], "gold")

    def test_a_nonce_from_another_flow_is_refused(self):
        """The client accepts any outstanding nonce for the server, so a token
        minted for another flow, such as a login, would otherwise pass."""
        _, state = build_step_up_url("kc")
        other_url, _ = build_step_up_url("kc")
        other = parse_qs(urlparse(other_url).query)["nonce"][0]

        claims, _, reason = _redeem_with(
            {"acr": "gold", "nonce": other}, "kc", state, echo_nonce=False
        )

        self.assertIsNone(claims)
        self.assertEqual(reason, "nonce_mismatch")

    def test_a_token_without_a_nonce_is_refused(self):
        _, state = build_step_up_url("kc")
        self.assertTrue(flow_nonce(state))

        claims, _, reason = _redeem_with({"acr": "gold"}, "kc", state, echo_nonce=False)

        self.assertIsNone(claims)
        self.assertEqual(reason, "nonce_mismatch")

    def test_a_state_stored_without_a_nonce_is_refused(self):
        """States started before nonces were stored must be refused, not
        raise."""
        _, state = build_step_up_url("kc")
        key = _step_up_state_key(state)
        entry = {k: v for k, v in cache.get(key).items() if k != "nonce"}
        cache.set(key, entry, 300)

        claims, _, reason = _redeem_with(
            {"acr": "gold", "nonce": "anything"}, "kc", state, echo_nonce=False
        )

        self.assertIsNone(claims)
        self.assertEqual(reason, "nonce_mismatch")

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

    def test_the_configured_age_limit_is_the_one_applied(self):
        """120 rather than the default 300, so a setting that is ignored
        or misspelled fails here."""
        config = {**KEYCLOAK["STEP_UP"], "MAX_AUTH_AGE_SECONDS": 120}

        within = verify_assurance(
            {"acr": "gold", "auth_time": time.time() - 110}, config
        )
        beyond = verify_assurance(
            {"acr": "gold", "auth_time": time.time() - 130}, config
        )

        self.assertEqual(within, (True, ""))
        self.assertEqual(beyond, (False, "auth_time_stale"))

    def test_an_auth_time_too_large_for_a_float_is_refused(self):
        """JSON decodes a 400-digit number as an int that float() cannot
        hold."""
        satisfied, reason = verify_assurance(
            {"acr": "gold", "auth_time": 10**400}, KEYCLOAK["STEP_UP"]
        )

        self.assertFalse(satisfied)
        self.assertEqual(reason, "auth_time_absent")

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

    @override_settings(
        OPENID_CONNECT_VIEWSET_CONFIG={"MAP_CLAIM_TO_MODEL": {"upn": "email"}}
    )
    def test_a_claim_remapped_onto_the_email_field_is_safe(self):
        self.assertTrue(subject_binding_is_safe({"SUBJECT_CLAIM": "upn"}))

    def test_a_username_field_is_not_safe(self):
        self.assertFalse(subject_binding_is_safe({"SUBJECT_FIELD": "username"}))

    def test_the_default_falls_back_to_the_emails_list(self):
        claims = {"emails": ["ana@example.org"]}

        self.assertTrue(verify_subject(claims, "ana@example.org", {})[0])

    def test_a_list_valued_claim_matches_any_member(self):
        """Azure AD B2C sends ``emails``, a list."""
        config = {"SUBJECT_CLAIM": "emails", "SUBJECT_FIELD": "email"}
        claims = {"emails": ["old@example.org", "ana@example.org"]}

        self.assertTrue(verify_subject(claims, "ana@example.org", config)[0])
        self.assertFalse(verify_subject(claims, "bo@example.org", config)[0])


class TestPopupRendering(TestCase):
    def test_it_posts_the_grant_to_the_configured_origin(self):
        html = render_step_up_popup("https://app.example", grant="g-1")

        self.assertIn('"https://app.example"', html)
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

        with (
            patch(
                "oidc.stepup.OpenIDClient.retrieve_tokens_using_auth_code",
                side_effect=RuntimeError("upstream is down"),
            ),
            self.assertLogs("oidc.stepup", "ERROR") as logs,
        ):
            claims, _, reason = redeem_step_up("kc", "code", state)

        self.assertIsNone(claims)
        self.assertEqual(reason, "exchange_failed")
        # No traceback and no message: the failing frame holds the provider's
        # tokens and the PKCE verifier, and the message can echo them.
        self.assertEqual([r.exc_info for r in logs.records], [None])
        self.assertIn("RuntimeError", logs.output[0])
        self.assertIn("'kc'", logs.output[0])
        self.assertNotIn("upstream is down", logs.output[0])

    def test_a_string_claim_is_not_split_into_characters(self):
        """set("gold") is {"g","o","l","d"}, which can intersect a
        single-character accepted value by accident."""
        config = {
            "CLAIM": "amr",
            "SATISFIED_BY": ["g"],
            "REQUIRE_AUTH_TIME": False,
        }

        self.assertFalse(verify_assurance({"amr": "gold"}, config)[0])

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
