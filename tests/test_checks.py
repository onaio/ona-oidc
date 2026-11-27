"""Tests for module oidc.checks"""

from django.core.checks import Tags, run_checks
from django.test import SimpleTestCase, TestCase, override_settings

from oidc.checks import (
    check_step_up_configuration,
    check_step_up_demands_fresh_authentication,
    check_step_up_grants_use_a_shared_cache,
)
from tests.test_stepup import KEYCLOAK, SERVERS

BODY_MODE_SERVERS = {
    "modern": {"REQUEST_MODE": "form_post"},
    "default": {},
}
MIXED_MODE_SERVERS = {
    "legacy": {"REQUEST_MODE": "query"},
    "partner": {"REQUEST_MODE": "query"},
    **BODY_MODE_SERVERS,
}


def request_mode_warnings():
    """Messages of the oidc.W003 warnings the configured settings raise"""
    return [m.msg for m in run_checks() if m.id == "oidc.W003"]


class RequestModeCheckTestCase(SimpleTestCase):
    """Tests for the REQUEST_MODE system check"""

    @override_settings(OPENID_CONNECT_AUTH_SERVERS=MIXED_MODE_SERVERS)
    def test_query_request_mode_warns(self):
        """Each auth server in query mode gets a warning"""
        warnings = request_mode_warnings()

        self.assertEqual(len(warnings), 2)
        self.assertIn("legacy", warnings[0])
        self.assertIn("partner", warnings[1])

    @override_settings(OPENID_CONNECT_AUTH_SERVERS=None)
    def test_unset_auth_servers_do_not_crash_checks(self):
        """An unset auth server setting raises no warning and no error"""
        self.assertEqual(request_mode_warnings(), [])


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


def _with_step_up(**overrides):
    return {"kc": {**KEYCLOAK, "STEP_UP": {**KEYCLOAK["STEP_UP"], **overrides}}}


class TestStepUpConfigurationCheck(TestCase):
    """Settings that would otherwise fail only after the user has proved a
    factor at the provider, or crash the callback, are refused at startup."""

    @override_settings(OPENID_CONNECT_AUTH_SERVERS=SERVERS)
    def test_a_complete_configuration_is_silent(self):
        self.assertEqual(check_step_up_configuration(), [])

    def test_each_misconfiguration_is_an_error(self):
        broken = {
            "a STEP_UP that is not a dict": {"kc": {**KEYCLOAK, "STEP_UP": True}},
            "no REDIRECT_URI": _with_step_up(REDIRECT_URI=None),
            "no CLAIM": _with_step_up(CLAIM=""),
            "a list CLAIM": _with_step_up(CLAIM=["acr"]),
            "a list SUBJECT_CLAIM": _with_step_up(SUBJECT_CLAIM=["email"]),
            "an empty SUBJECT_CLAIM": _with_step_up(SUBJECT_CLAIM=""),
            "a list SUBJECT_FIELD": _with_step_up(SUBJECT_FIELD=["email"]),
            "no SATISFIED_BY": _with_step_up(SATISFIED_BY=[]),
            "a string SATISFIED_BY": _with_step_up(SATISFIED_BY="gold"),
            "an int SATISFIED_BY": _with_step_up(SATISFIED_BY=2),
            "a SATISFIED_BY nothing can match": _with_step_up(
                SATISFIED_BY=[None, True, 2.0]
            ),
            "a text MAX_AUTH_AGE_SECONDS": _with_step_up(MAX_AUTH_AGE_SECONDS="300"),
            "a zero MAX_AUTH_AGE_SECONDS": _with_step_up(MAX_AUTH_AGE_SECONDS=0),
            "a bool MAX_AUTH_AGE_SECONDS": _with_step_up(MAX_AUTH_AGE_SECONDS=True),
            "a text MAX_AGE": _with_step_up(MAX_AGE="0"),
            "a negative MAX_AGE": _with_step_up(MAX_AGE=-1),
        }
        for case, servers in broken.items():
            with (
                self.subTest(case),
                override_settings(OPENID_CONNECT_AUTH_SERVERS=servers),
            ):
                self.assertEqual(
                    [e.id for e in check_step_up_configuration()], ["oidc.E003"]
                )

    def test_a_grant_ttl_that_is_not_a_positive_int_is_an_error(self):
        for ttl in (0, -5, "five", True, float("inf")):
            with (
                self.subTest(ttl=ttl),
                override_settings(
                    OPENID_CONNECT_AUTH_SERVERS=SERVERS, STEP_UP_GRANT_TTL=ttl
                ),
            ):
                self.assertEqual(
                    [e.id for e in check_step_up_configuration()], ["oidc.E003"]
                )

    def test_shapes_that_work_at_runtime_are_accepted(self):
        """A frozenset level list, a numeric-string grant TTL and an explicit
        MAX_AGE of None (sent as 0) all work when a step-up runs, so refusing
        them at startup would be wrong."""
        with override_settings(
            OPENID_CONNECT_AUTH_SERVERS=_with_step_up(SATISFIED_BY=frozenset({"gold"})),
            STEP_UP_GRANT_TTL="300",
        ):
            self.assertEqual(check_step_up_configuration(), [])
        with override_settings(OPENID_CONNECT_AUTH_SERVERS=_with_step_up(MAX_AGE=None)):
            self.assertEqual(check_step_up_configuration(), [])
        with override_settings(
            OPENID_CONNECT_AUTH_SERVERS=_with_step_up(
                SUBJECT_CLAIM=None, SUBJECT_FIELD="email"
            )
        ):
            self.assertEqual(check_step_up_configuration(), [])

    @override_settings(OPENID_CONNECT_AUTH_SERVERS={"login-only": {"STEP_UP": {}}})
    def test_no_step_up_server_is_silent(self):
        self.assertEqual(check_step_up_configuration(), [])

    @override_settings(
        OPENID_CONNECT_AUTH_SERVERS={"kc": {**KEYCLOAK, "STEP_UP": True}}
    )
    def test_the_warnings_survive_a_step_up_that_is_not_a_dict(self):
        """System checks run on every manage.py command; one that raises
        takes all of them down."""
        self.assertEqual(check_step_up_demands_fresh_authentication(), [])


class TestChecksAreRegistered(TestCase):
    @override_settings(
        OPENID_CONNECT_AUTH_SERVERS=_with_step_up(CLAIM="", MAX_AGE=600),
        CACHES=_LOCMEM,
    )
    def test_the_app_registers_its_step_up_checks(self):
        ids = {message.id for message in run_checks(tags=[Tags.security])}

        self.assertTrue({"oidc.E003", "oidc.W001", "oidc.W002"} <= ids)

    @override_settings(OPENID_CONNECT_AUTH_SERVERS={"kc": "not a dict"})
    def test_a_server_that_is_not_a_dict_does_not_crash_the_step_up_checks(self):
        self.assertEqual(check_step_up_configuration(), [])
        self.assertEqual(check_step_up_demands_fresh_authentication(), [])
        self.assertEqual(check_step_up_grants_use_a_shared_cache(), [])
