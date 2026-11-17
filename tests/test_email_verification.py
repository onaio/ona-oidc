"""
Tests for the callback's ``email_verified`` checks
"""

from unittest.mock import patch

from django.conf import settings
from django.contrib.auth import get_user_model
from django.core.cache import cache
from django.core.exceptions import ImproperlyConfigured
from django.test import TestCase
from django.test.utils import override_settings

from rest_framework.test import APIRequestFactory

from oidc.client import OpenIDClient, state_cache_key
from oidc.viewsets import UserModelOpenIDConnectViewset

User = get_user_model()

CLAIMS = {
    "given_name": "Jane",
    "family_name": "Doe",
    "email": "jane@example.com",
    "preferred_username": "jane",
}


def auth_servers(**overrides) -> dict:
    """Return the test auth servers with ``overrides`` on the default one."""
    return {
        **settings.OPENID_CONNECT_AUTH_SERVERS,
        "default": {**settings.OPENID_CONNECT_AUTH_SERVERS["default"], **overrides},
    }


@override_settings(OPENID_CONNECT_AUTH_SERVERS=auth_servers(CHECK_EMAIL_VERIFIED=True))
class EmailVerifiedTestCase(TestCase):
    def setUp(self):
        self.factory = APIRequestFactory()
        cache.clear()
        self.user = User.objects.create_user(
            username="existing", email="jane@example.com"
        )

    def _callback(self, claims: dict):
        view = UserModelOpenIDConnectViewset.as_view({"post": "callback"})
        with patch.object(
            OpenIDClient, "verify_and_decode_id_token", return_value=claims
        ):
            request = self.factory.post("/", data={"id_token": "h.p.s"})
            return view(request, auth_server="default")

    def _assert_refused(self, response):
        self.assertEqual(response.status_code, 401)
        self.assertEqual(response.data["error_title"], "Email address not verified")
        self.assertNotIn("SSO", response.cookies)
        self.user.refresh_from_db()
        self.assertIsNone(self.user.last_login)

    def _assert_linked(self, response):
        self.assertEqual(response.status_code, 302)
        self.user.refresh_from_db()
        self.assertIsNotNone(self.user.last_login)

    def test_unverified_email_does_not_link_to_an_existing_account(self):
        """An ``email_verified`` that is not true refuses the login."""
        for name, value in {
            "false": False,
            "string false": "false",
            "null": None,
            "number": 1,
        }.items():
            with self.subTest(name):
                with self.assertLogs("oidc.viewsets", level="WARNING") as logs:
                    response = self._callback({**CLAIMS, "email_verified": value})
                self._assert_refused(response)
                self.assertIn("email address not verified", "\n".join(logs.output))

    def test_unverified_email_in_emails_list_does_not_link(self):
        """The ``emails`` list is matched only when the address is verified."""
        claims = {k: v for k, v in CLAIMS.items() if k != "email"}
        response = self._callback(
            {**claims, "emails": ["jane@example.com"], "email_verified": False}
        )
        self._assert_refused(response)

    def test_unverified_email_does_not_create_an_account(self):
        """With no matching account, an unverified address creates none.

        An account created from an unverified address would be linked to
        the address owner when they first sign in.
        """
        self.user.delete()
        response = self._callback(
            {**CLAIMS, "email": "new@example.com", "email_verified": False}
        )
        self.assertEqual(response.status_code, 401)
        self.assertEqual(response.data["error_title"], "Email address not verified")
        self.assertFalse(User.objects.filter(email__iexact="new@example.com").exists())

    def test_verified_email_links_to_the_existing_account(self):
        """An ``email_verified`` of true, or the string "true", links."""
        for name, value in {
            "true": True,
            "string true": "true",
            "string true with case and spaces": " TRUE ",
        }.items():
            with self.subTest(name):
                self.user.last_login = None
                self.user.save(update_fields=["last_login"])
                self._assert_linked(self._callback({**CLAIMS, "email_verified": value}))

    def test_missing_claim_links_by_default(self):
        """Without the claim, the address is trusted unless the server opts in."""
        self._assert_linked(self._callback(CLAIMS))

    @override_settings(OPENID_CONNECT_AUTH_SERVERS=auth_servers())
    def test_unverified_email_links_when_the_check_is_off(self):
        """With ``CHECK_EMAIL_VERIFIED`` at its default, the claim is ignored."""
        self._assert_linked(self._callback({**CLAIMS, "email_verified": False}))

    @override_settings(
        OPENID_CONNECT_AUTH_SERVERS=auth_servers(REQUIRE_VERIFIED_EMAIL=True)
    )
    def test_missing_claim_is_refused_when_required(self):
        """With ``REQUIRE_VERIFIED_EMAIL``, a missing claim refuses the login.

        ``CHECK_EMAIL_VERIFIED`` is left at its default here, because
        ``REQUIRE_VERIFIED_EMAIL`` turns the check on by itself.
        """
        self._assert_refused(self._callback(CLAIMS))
        self._assert_refused(self._callback({**CLAIMS, "email_verified": False}))
        self._assert_linked(self._callback({**CLAIMS, "email_verified": True}))

    def test_blank_email_does_not_link_to_a_blank_email_account(self):
        """A blank address matches no account, verified or not.

        Claims without a usable address go to userinfo, so the userinfo
        result is patched to return the same claims.
        """
        blank = User.objects.create_user(username="blank", email="")
        self.assertTrue(User.objects.filter(email__iexact="").exists())
        no_email = {k: v for k, v in CLAIMS.items() if k != "email"}
        cases = {
            "verified, check on": (
                {**no_email, "email": "", "email_verified": True},
                auth_servers(CHECK_EMAIL_VERIFIED=True),
            ),
            "unverified, check off": (
                {**no_email, "email": "", "email_verified": False},
                auth_servers(CHECK_EMAIL_VERIFIED=False),
            ),
            "whitespace": (
                {**no_email, "email": "  ", "email_verified": True},
                auth_servers(CHECK_EMAIL_VERIFIED=True),
            ),
            "blank emails entries": (
                {**no_email, "emails": ["", " "], "email_verified": True},
                auth_servers(CHECK_EMAIL_VERIFIED=True),
            ),
        }
        for name, (claims, servers) in cases.items():
            with (
                self.subTest(name),
                override_settings(OPENID_CONNECT_AUTH_SERVERS=servers),
                patch.object(OpenIDClient, "tokens_to_user_info", return_value=claims),
            ):
                blank.last_login = None
                blank.save(update_fields=["last_login"])
                response = self._callback(claims)
                self.assertEqual(response.status_code, 400)
                self.assertEqual(
                    response.data["error_title"], "Missing details in ID Token"
                )
                self.assertNotIn("SSO", response.cookies)
                blank.refresh_from_db()
                self.assertIsNone(blank.last_login)
                self.assertEqual(User.objects.count(), 2)

    def test_blank_addresses_are_skipped_for_the_next_usable_one(self):
        """A blank ``email`` or ``emails`` entry gives way to a real address."""
        blank = User.objects.create_user(username="blank", email="")
        no_email = {k: v for k, v in CLAIMS.items() if k != "email"}
        for name, claims in {
            "blank email": {**no_email, "email": "", "emails": ["jane@example.com"]},
            "blank first entry": {**no_email, "emails": ["", "jane@example.com"]},
        }.items():
            with self.subTest(name):
                self.user.last_login = None
                self.user.save(update_fields=["last_login"])
                self._assert_linked(self._callback({**claims, "email_verified": True}))
                blank.refresh_from_db()
                self.assertIsNone(blank.last_login)

    def test_no_address_skips_user_defaults_groups(self):
        """``USER_DEFAULTS`` groups are matched only against a real address."""
        config = {
            **settings.OPENID_CONNECT_VIEWSET_CONFIG,
            "REQUIRED_USER_CREATION_FIELDS": ["first_name", "username"],
            "USER_DEFAULTS": {r"^.*@ona\.io$": {"is_active": False}},
        }
        claims = {**CLAIMS, "email": "", "email_verified": True}
        self.user.delete()
        with (
            override_settings(OPENID_CONNECT_VIEWSET_CONFIG=config),
            patch.object(OpenIDClient, "tokens_to_user_info", return_value=claims),
        ):
            response = self._callback(claims)
        self.assertEqual(response.status_code, 302)
        created = User.objects.get()
        self.assertEqual(created.email, "")
        self.assertTrue(created.is_active)

    @override_settings(
        OPENID_CONNECT_AUTH_SERVERS=auth_servers(REQUIRE_VERIFIED_EMAIL=True)
    )
    def test_claims_without_an_email_are_not_checked(self):
        """There is nothing to verify when the claims carry no address.

        Claims without an address send the callback to userinfo, so the
        userinfo result is patched to return the same claims.
        """
        claims = {k: v for k, v in CLAIMS.items() if k != "email"}
        with patch.object(OpenIDClient, "tokens_to_user_info", return_value=claims):
            response = self._callback(claims)
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.data["error_title"], "Missing details in ID Token")

    @override_settings(
        OPENID_CONNECT_AUTH_SERVERS=auth_servers(
            CHECK_EMAIL_VERIFIED=True,
            RESPONSE_TYPE="code",
            USE_PKCE=True,
            TOKEN_ENDPOINT="https://idp/token",
        )
    )
    def test_refusal_clears_the_login_state(self):
        """A refused login drops its cached PKCE verifier."""
        state = "pkce-state"
        cache.set(state_cache_key(state), "verifier")
        view = UserModelOpenIDConnectViewset.as_view({"post": "callback"})
        with (
            patch.object(
                OpenIDClient,
                "retrieve_tokens_using_auth_code",
                return_value={"id_token": "h.p.s"},
            ),
            patch.object(
                OpenIDClient,
                "verify_and_decode_id_token",
                return_value={**CLAIMS, "email_verified": False},
            ),
        ):
            request = self.factory.post("/", data={"state": state, "code": "c"})
            response = view(request, auth_server="default")
        self._assert_refused(response)
        self.assertIsNone(cache.get(state_cache_key(state)))


class EmailVerifiedSettingsTestCase(TestCase):
    def test_defaults_to_off(self):
        """Both settings are off when the server does not set them."""
        server = settings.OPENID_CONNECT_AUTH_SERVERS["default"]
        self.assertNotIn("CHECK_EMAIL_VERIFIED", server)
        self.assertNotIn("REQUIRE_VERIFIED_EMAIL", server)
        client = OpenIDClient("default")
        self.assertFalse(client.check_email_verified)
        self.assertFalse(client.require_verified_email)

    @override_settings(
        OPENID_CONNECT_AUTH_SERVERS=auth_servers(CHECK_EMAIL_VERIFIED="True")
    )
    def test_reads_the_per_server_check_setting(self):
        """``CHECK_EMAIL_VERIFIED`` is read per server, as a bool or string."""
        client = OpenIDClient("default")
        self.assertTrue(client.check_email_verified)
        self.assertFalse(client.require_verified_email)

    @override_settings(
        OPENID_CONNECT_AUTH_SERVERS=auth_servers(REQUIRE_VERIFIED_EMAIL="True")
    )
    def test_reads_the_per_server_require_setting(self):
        """``REQUIRE_VERIFIED_EMAIL`` is read per server and turns the check on."""
        client = OpenIDClient("default")
        self.assertTrue(client.require_verified_email)
        self.assertTrue(client.check_email_verified)

    @override_settings(
        OPENID_CONNECT_AUTH_SERVERS=auth_servers(
            REQUIRE_VERIFIED_EMAIL=True, CHECK_EMAIL_VERIFIED="flase"
        )
    )
    def test_invalid_check_setting_is_rejected_when_required_is_on(self):
        """``CHECK_EMAIL_VERIFIED`` is validated even when it has no effect."""
        with self.assertRaises(ImproperlyConfigured):
            OpenIDClient("default")
