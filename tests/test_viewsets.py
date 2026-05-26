"""
Tests for the OpenID Client
"""

import json

from django.contrib.auth import get_user_model
from django.core.cache import cache
from django.core.exceptions import ImproperlyConfigured
from django.test import TestCase
from django.test.utils import override_settings
from django.utils import timezone

import jwt
from mock import MagicMock, patch
from rest_framework.test import APIRequestFactory

from oidc.client import OpenIDClient, TokenVerificationFailed, state_cache_key
from oidc.viewsets import (
    DEFAULT_USERNAME_HELP_TEXT,
    DEFAULT_USERNAME_PATTERN,
    USERNAME_FORM_MARKER_FIELD,
    USERNAME_FORM_MARKER_VALUE,
    BaseOpenIDConnectViewset,
    UserModelOpenIDConnectViewset,
)

User = get_user_model()

OPENID_CONNECT_AUTH_SERVERS = {
    "default": {
        "AUTHORIZATION_ENDPOINT": "https://example.com/oauth2/v2.0/authorize",
        "CLIENT_ID": "client",
        "JWKS_ENDPOINT": "https://example.com/discovery/v2.0/keys",
        "SCOPE": "openid profile",
        "TOKEN_ENDPOINT": "https://example.com/oauth2/v2.0/token",
        "END_SESSION_ENDPOINT": "http://localhost:3000",
        "REDIRECT_URI": "http://localhost:8000/oidc/msft/callback",
        "RESPONSE_TYPE": "code",
        "RESPONSE_MODE": "form_post",
        "USE_NONCES": False,
    },
    "pkce": {
        "AUTHORIZATION_ENDPOINT": "https://example.com/oauth2/v2.0/authorize",
        "CLIENT_ID": "client",
        "JWKS_ENDPOINT": "https://example.com/discovery/v2.0/keys",
        "SCOPE": "openid profile",
        "TOKEN_ENDPOINT": "https://example.com/oauth2/v2.0/token",
        "END_SESSION_ENDPOINT": "http://localhost:3000",
        "REDIRECT_URI": "http://localhost:8000/oidc/msft/callback",
        "RESPONSE_TYPE": "code",
        "USE_NONCES": False,
        "RESPONSE_MODE": "form_post",
        "USE_PKCE": True,
        "PKCE_CODE_CHALLENGE_METHOD": "S256",
        "PKCE_CODE_CHALLENGE_TIMEOUT": 600,
        "PKCE_CODE_VERIFIER_LENGTH": 128,
    },
}
OPENID_CONNECT_VIEWSET_CONFIG = {
    "REQUIRED_USER_CREATION_FIELDS": ["email", "first_name", "username"],
    "USER_CREATION_FIELDS": ["email", "first_name", "last_name", "username"],
    "MAP_CLAIM_TO_MODEL": {
        "given_name": "first_name",
        "family_name": "last_name",
        "preferred_username": "username",
        "sub": "email",
    },
    "USER_DEFAULTS": {
        "default": {"is_active": False},
        "^.*@ona.io$": {"is_active": True},
    },
    "SPLIT_NAME_CLAIM": True,
    "USE_EMAIL_USERNAME": True,
    "USER_UNIQUE_FILTER_FIELDS": ["email", "username"],
    "SSO_COOKIE_DATA": "email",
    "JWT_ALGORITHM": "HS256",
    "JWT_SECRET_KEY": "abc",
    "REPLACE_USERNAME_CHARACTERS": "-.",
    "FIELD_VALIDATION_REGEX": {
        "username": {
            "regex": r"^(?!\d+$)[a-zA-Z0-9_]{3,}$",
            "help_text": "Username should only contain word characters & numbers and should have 3 or more characters",
        },
    },
    "SSO_COOKIE_DOMAIN": ".example.com",
    "SSO_COOKIE_MAX_AGE": 60 * 60 * 24 * 30,
}


class TestUserModelOpenIDConnectViewset(TestCase):
    """
    Test class for the OpenID Connect class
    """

    def setUp(self):
        TestCase().setUp()
        self.factory = APIRequestFactory()
        # Clear the cache
        cache.clear()

    def test_returns_data_entry_template_on_missing_username_claim(self):
        """
        Test that users are redirected to the data entry
        page when username is not present in decoded token
        """
        view = UserModelOpenIDConnectViewset.as_view({"post": "callback"})
        with patch(
            "oidc.viewsets.OpenIDClient.verify_and_decode_id_token"
        ) as mock_func:
            mock_func.return_value = {
                "family_name": "bob",
                "given_name": "just bob",
                "email": "bob@example.com",
            }

            data = {"id_token": "sadsdaio3209lkasdlkas0d.sdojdsiad.iosdadia"}
            request = self.factory.post("/", data=data)
            response = view(request, auth_server="default")
            self.assertEqual(response.status_code, 200)
            self.assertEqual(response.template_name, "oidc/oidc_user_data_entry.html")

    @override_settings(OPENID_CONNECT_VIEWSET_CONFIG=OPENID_CONNECT_VIEWSET_CONFIG)
    def test_username_form_resubmit_clears_state_cache(self):
        """
        On a successful re-submit of the username-entry form, the cache
        entry that client.login() wrote against the OIDC `state` value
        must be deleted by _clear_login_states. The form carries the
        original `state` back as a hidden input, the short-circuit
        threads it into server_response, and cleanup runs as on the
        non-form-render path. Without this, the entry leaks until cache
        TTL on every missing-username flow.
        """
        # Prime the cache the way client.login() actually writes it
        # (namespaced via state_cache_key).
        state = "known-state-value"
        cache.set(state_cache_key(state), "known-code-verifier")
        view = UserModelOpenIDConnectViewset.as_view({"post": "callback"})
        with patch(
            "oidc.viewsets.OpenIDClient.verify_and_decode_id_token"
        ) as mock_decode:
            mock_decode.return_value = {
                "name": "Cache User",
                "preferred_username": "cacheuser@example.com",
                "given_name": "cache",
                "family_name": "User",
                "email": "cacheuser@example.com",
            }
            request = self.factory.post(
                "/",
                data={
                    "id_token": "sadsdaio3209lkasdlkas0d.sdojdsiad.iosdadia",
                    "username": "cache_chosen",
                    "state": state,
                    USERNAME_FORM_MARKER_FIELD: USERNAME_FORM_MARKER_VALUE,
                },
            )
            response = view(request, auth_server="default")
            self.assertEqual(response.status_code, 302)
            self.assertIsNone(cache.get(state_cache_key(state)))

    @override_settings(OPENID_CONNECT_VIEWSET_CONFIG=OPENID_CONNECT_VIEWSET_CONFIG)
    def test_form_resubmit_attacker_state_does_not_touch_unrelated_cache_entries(self):
        """
        Security boundary: an attacker holding a valid id_token can drive
        the form re-submit short-circuit with an arbitrary `state` value
        in the body. _clear_login_states must only delete entries inside
        the OIDC `oidc:state:` keyspace, never raw keys that other apps
        (Django sessions, rate-limit counters, feature flags, etc.) own.
        Pins the state-cache-key namespace as the security boundary.
        """
        cache.set("unrelated-app-key", "important-data")
        view = UserModelOpenIDConnectViewset.as_view({"post": "callback"})
        with patch(
            "oidc.viewsets.OpenIDClient.verify_and_decode_id_token"
        ) as mock_decode:
            mock_decode.return_value = {
                "name": "Attacker User",
                "preferred_username": "attacker@example.com",
                "given_name": "att",
                "family_name": "Acker",
                "email": "attacker@example.com",
            }
            request = self.factory.post(
                "/",
                data={
                    "id_token": "sadsdaio3209lkasdlkas0d.sdojdsiad.iosdadia",
                    "username": "att_chosen",
                    # Attacker chooses the cache key they want deleted.
                    "state": "unrelated-app-key",
                    USERNAME_FORM_MARKER_FIELD: USERNAME_FORM_MARKER_VALUE,
                },
            )
            response = view(request, auth_server="default")
            self.assertEqual(response.status_code, 302)
            # The unrelated entry is untouched. Only the namespaced
            # equivalent (oidc:state:unrelated-app-key) — which doesn't
            # exist — would have been deleted.
            self.assertEqual(cache.get("unrelated-app-key"), "important-data")

    @override_settings(OPENID_CONNECT_VIEWSET_CONFIG=OPENID_CONNECT_VIEWSET_CONFIG)
    def test_form_post_mode_post_with_id_token_no_marker_uses_request_data(self):
        """
        Symmetric to the query-mode security regression: in the default
        response_mode=form_post, a POST that carries an `id_token` in
        the body but NOT the form marker must follow the existing
        `server_response = request.data` branch unchanged. The new
        short-circuit must not alter form_post semantics for callers
        that aren't our re-submit form (i.e., the IdP itself).

        Limitation: the assertions below (`mock_exchange.assert_not_called`
        + `mock_decode.assert_called_once_with(...)`) hold whether the
        form_post branch or the short-circuit branch ran — both source
        the id_token from request.data and skip the auth-code exchange.
        This is therefore a behavioural pin, not a code-path pin.
        """
        view = UserModelOpenIDConnectViewset.as_view({"post": "callback"})
        with (
            patch(
                "oidc.viewsets.OpenIDClient.retrieve_tokens_using_auth_code"
            ) as mock_exchange,
            patch(
                "oidc.viewsets.OpenIDClient.verify_and_decode_id_token"
            ) as mock_decode,
        ):
            mock_decode.return_value = {
                "name": "FormPost User",
                "preferred_username": "fpuser@example.com",
                "given_name": "fp",
                "family_name": "User",
                "email": "fpuser@example.com",
            }
            # No marker, no ?code= in URL: id_token comes from request.data
            # via the form_post branch. Exchange must never be attempted.
            request = self.factory.post(
                "/",
                data={"id_token": "idp-supplied-id-token"},
            )
            response = view(request, auth_server="default")
            self.assertEqual(response.status_code, 302)
            mock_exchange.assert_not_called()
            mock_decode.assert_called_once_with("idp-supplied-id-token")

    @override_settings(OPENID_CONNECT_VIEWSET_CONFIG=OPENID_CONNECT_VIEWSET_CONFIG)
    def test_username_form_resubmit_does_not_re_exchange_code(self):
        """
        When the user-data-entry form re-POSTs to the callback URL, the
        original OIDC `?code=...` is still on the URL because the form's
        action="" preserves the query string. The viewset must NOT try to
        re-exchange that one-shot code (which would 400 from the IdP as
        invalid_code) — it should use the id_token already in the form
        body. The form sends a `from_username_form=1` marker that gates
        this short-circuit.
        """
        view = UserModelOpenIDConnectViewset.as_view({"post": "callback"})
        with (
            patch(
                "oidc.viewsets.OpenIDClient.retrieve_tokens_using_auth_code"
            ) as mock_exchange,
            patch(
                "oidc.viewsets.OpenIDClient.verify_and_decode_id_token"
            ) as mock_decode,
        ):
            mock_decode.return_value = {
                "email_verified": False,
                "name": "Bob User",
                "preferred_username": "bob@example.com",
                "given_name": "bob",
                "family_name": "User",
                "email": "bob@example.com",
            }
            request = self.factory.post(
                "/?code=stale-already-consumed-code&state=stale-state",
                data={
                    "id_token": "sadsdaio3209lkasdlkas0d.sdojdsiad.iosdadia",
                    "username": "bob_chosen",
                    USERNAME_FORM_MARKER_FIELD: USERNAME_FORM_MARKER_VALUE,
                },
            )
            response = view(request, auth_server="default")
            self.assertEqual(response.status_code, 302)
            mock_exchange.assert_not_called()
            self.assertTrue(User.objects.filter(username="bob_chosen").exists())

    @override_settings(
        OPENID_CONNECT_AUTH_SERVERS={
            "default": {
                **OPENID_CONNECT_AUTH_SERVERS["default"],
                "RESPONSE_MODE": "query",
            }
        },
        OPENID_CONNECT_VIEWSET_CONFIG=OPENID_CONNECT_VIEWSET_CONFIG,
    )
    def test_query_mode_post_with_id_token_but_no_form_marker_uses_code_exchange(self):
        """
        Security regression: a POST to /callback carrying an id_token in
        the body but WITHOUT the form marker must NOT short-circuit the
        auth-code exchange for clients configured with response_mode=query.
        Otherwise any holder of a signed id_token could bypass the
        state/nonce validation tied to the auth-code flow.
        """
        view = UserModelOpenIDConnectViewset.as_view({"post": "callback"})
        with (
            patch(
                "oidc.viewsets.OpenIDClient.retrieve_tokens_using_auth_code"
            ) as mock_exchange,
            patch(
                "oidc.viewsets.OpenIDClient.verify_and_decode_id_token"
            ) as mock_decode,
        ):
            # Make the exchange fail so we don't accidentally exercise
            # the rest of the flow. We pin two invariants:
            #   1. The code from the URL IS exchanged.
            #   2. The id_token from the body is NEVER decoded.
            mock_exchange.side_effect = TokenVerificationFailed("test stop")
            request = self.factory.post(
                "/?code=fresh-code-from-idp",
                data={"id_token": "attacker-supplied-id-token"},
            )
            response = view(request, auth_server="default")
            mock_exchange.assert_called_once()
            self.assertEqual(mock_exchange.call_args[0][0], "fresh-code-from-idp")
            for call in mock_decode.call_args_list:
                self.assertNotIn("attacker-supplied-id-token", call.args)
            self.assertEqual(response.status_code, 401)

    @override_settings(
        OPENID_CONNECT_VIEWSET_CONFIG={
            **OPENID_CONNECT_VIEWSET_CONFIG,
            # Disable email-derived username so the missing-username
            # path actually renders the form (instead of auto-deriving
            # a value the permissive regex below would happily accept).
            "USE_EMAIL_USERNAME": False,
            "FIELD_VALIDATION_REGEX": {
                "username": {
                    "regex": r"(?!^\d+$)^.+$",
                    "help_text": "Custom validation help",
                },
            },
        }
    )
    def test_username_form_pattern_and_title_come_from_config(self):
        """
        The form's HTML5 `pattern` and `title` attributes must reflect
        the configured FIELD_VALIDATION_REGEX["username"]["regex"] and
        ["help_text"], not the legacy hard-coded `^[A-Za-z0-9_]*$`.
        Otherwise a deployment with a permissive regex sees its
        prefill rejected by the browser even though the server-side
        validator would accept it.
        """
        view = UserModelOpenIDConnectViewset.as_view({"post": "callback"})
        with patch(
            "oidc.viewsets.OpenIDClient.verify_and_decode_id_token"
        ) as mock_func:
            mock_func.return_value = {
                "family_name": "bob",
                "given_name": "just bob",
                "email": "bob@example.com",
            }
            data = {"id_token": "sadsdaio3209lkasdlkas0d.sdojdsiad.iosdadia"}
            request = self.factory.post("/", data=data)
            response = view(request, auth_server="default")
            self.assertEqual(response.status_code, 200)
            self.assertEqual(response.template_name, "oidc/oidc_user_data_entry.html")
            # The configured regex is forwarded as-is; HTML5 `pattern`
            # already implicitly full-matches the input value.
            self.assertEqual(response.data["username_pattern"], r"(?!^\d+$)^.+$")
            self.assertEqual(
                response.data["username_help_text"], "Custom validation help"
            )

    def test_username_field_config_falls_back_to_defaults(self):
        """
        When FIELD_VALIDATION_REGEX has no `username` entry, the helper
        falls back to the module-level defaults so the rendered template
        keeps its legacy behaviour for deployments that haven't
        customized validation.
        """
        viewset = BaseOpenIDConnectViewset()
        viewset.field_validation_regex = {}
        regex, help_text = viewset._username_field_config()
        self.assertEqual(regex, DEFAULT_USERNAME_PATTERN)
        self.assertEqual(help_text, DEFAULT_USERNAME_HELP_TEXT)

    def test_username_form_template_uses_marker_constants(self):
        """
        The form template hard-codes the marker field name and value;
        the viewset reads them via constants. Pin that the two stay
        in sync — a rename in viewsets.py without a template update
        (or vice versa) silently breaks the form-resubmit gate.
        """
        from django.template.loader import render_to_string

        rendered = render_to_string(
            "oidc/oidc_user_data_entry.html",
            {
                "id_token": "tok",
                "username_pattern": "^test$",
                "username_help_text": "test help",
            },
        )
        self.assertIn(f'name="{USERNAME_FORM_MARKER_FIELD}"', rendered)
        self.assertIn(f'value="{USERNAME_FORM_MARKER_VALUE}"', rendered)

    @override_settings(OPENID_CONNECT_VIEWSET_CONFIG=OPENID_CONNECT_VIEWSET_CONFIG)
    def test_create_user_providing_id_token_in_form(self):
        """
        Trying to create a user that already exists will ask you to chose a different username
        """
        view = UserModelOpenIDConnectViewset.as_view({"post": "callback"})
        with patch(
            "oidc.viewsets.OpenIDClient.verify_and_decode_id_token"
        ) as mock_func:
            mock_func.return_value = {
                "email_verified": False,
                "name": "Alice User",
                "preferred_username": "useralice@gmail.com",
                "given_name": "user",
                "family_name": "Alice",
                "email": "useralice@gmail.com",
            }

            data = {
                "id_token": "sadsdaio3209lkasdlkas0d.sdojdsiad.iosdadia",
            }
            request = self.factory.post("/", data=data)
            response = view(request, auth_server="default")
            self.assertEqual(response.status_code, 302)
            user = User.objects.get(username="useralice")
            self.assertEqual(user.email, "useralice@gmail.com")

        # when email username is already in use erorr message should reflect that
        with patch(
            "oidc.viewsets.OpenIDClient.verify_and_decode_id_token"
        ) as mock_func:
            mock_func.return_value = {
                "email_verified": False,
                "name": "Alice User",
                "preferred_username": "useralice@ona.io",
                "given_name": "user",
                "family_name": "Alice",
                "email": "useralice@ona.io",
            }

            data = {
                "id_token": "sadsdaio3209lkasdlkas0d.sdojdsiad.iosdadia",
            }
            request = self.factory.post("/", data=data)
            response = view(request, auth_server="default")

            self.assertEqual(user.email, "useralice@gmail.com")
            self.assertEqual(response.template_name, "oidc/oidc_user_data_entry.html")
            self.assertEqual(response.status_code, 200)
            self.assertEqual(
                response.data["error"],
                "Username field is already in use.",
            )

        # when preferred username is provided, use the preferred username
        with patch(
            "oidc.viewsets.OpenIDClient.verify_and_decode_id_token"
        ) as mock_func:
            mock_func.return_value = {
                "email_verified": False,
                "name": "Alice User",
                "preferred_username": "useralice@ona.io",
                "given_name": "user",
                "family_name": "Alice",
                "email": "useralice@ona.io",
            }

            data = {
                "id_token": "sadsdaio3209lkasdlkas0d.sdojdsiad.iosdadia",
                "username": "preferredusername",
            }
            request = self.factory.post("/", data=data)
            response = view(request, auth_server="default")

            self.assertEqual(user.email, "useralice@gmail.com")
            self.assertEqual(response.status_code, 302)
            user = User.objects.get(username="preferredusername")
            self.assertEqual(user.email, "useralice@ona.io")

    @override_settings(OPENID_CONNECT_VIEWSET_CONFIG=OPENID_CONNECT_VIEWSET_CONFIG)
    def test_recreating_already_existing_user(self):
        """
        Trying to create a user that already exists will ask you to chose a different username
        """
        view = UserModelOpenIDConnectViewset.as_view({"post": "callback"})
        with patch(
            "oidc.viewsets.OpenIDClient.verify_and_decode_id_token"
        ) as mock_func:
            mock_func.return_value = {
                "family_name": "Frankline",
                "given_name": "Benjamin",
                "username": "bfrank",
                "email": "bfrank@example.com",
            }

            data = {"id_token": "sadsdaio3209lkasdlkas0d.sdojdsiad.iosdadia"}
            request = self.factory.post("/", data=data)
            response = view(request, auth_server="default")
            # Creating the user for the first time will work ok
            self.assertEqual(response.status_code, 302)
            user = User.objects.get(username="bfrank")
            self.assertEqual(user.email, "bfrank@example.com")

        with patch(
            "oidc.viewsets.OpenIDClient.verify_and_decode_id_token"
        ) as mock_func:
            mock_func.return_value = {
                "family_name": "Frankline",
                "given_name": "Benjamin",
                "username": "bfrank",
                "email": "bfrank@ona.io",
            }

            data = {"id_token": "sadsdaio3209lkasdlkas0d.sdojdsiad.iosdadia"}
            request = self.factory.post("/", data=data)
            response = view(request, auth_server="default")
            # Creating the user for the second time will not work ok
            self.assertEqual(response.status_code, 200)

            response_data = json.loads(response.rendered_content.decode("utf-8"))
            self.assertEqual(
                "Username field is already in use.", response_data["error"]
            )
            self.assertEqual(response.template_name, "oidc/oidc_user_data_entry.html")

            # Original user with original email address still exists
            user = User.objects.get(username="bfrank")
            self.assertEqual(user.email, "bfrank@example.com")

        # Try creating the same user in uppercase
        with patch(
            "oidc.viewsets.OpenIDClient.verify_and_decode_id_token"
        ) as mock_func:
            mock_func.return_value = {
                "family_name": "Frankline",
                "given_name": "Benjamin",
                "username": "BFRANK",
                "email": "bfrank@ona.io",
            }

            data = {"id_token": "sadsdaio3209lkasdlkas0d.sdojdsiad.iosdadia"}
            request = self.factory.post("/", data=data)
            response = view(request, auth_server="default")
            # Creating the user for the second time will not work ok
            self.assertEqual(response.status_code, 200)

            response_data = json.loads(response.rendered_content.decode("utf-8"))
            self.assertEqual(
                "Username field is already in use.", response_data["error"]
            )
            self.assertEqual(response.template_name, "oidc/oidc_user_data_entry.html")

            # Original user with original email address still exists
            user = User.objects.get(username="bfrank")
            self.assertEqual(user.email, "bfrank@example.com")

    @override_settings(OPENID_CONNECT_VIEWSET_CONFIG=OPENID_CONNECT_VIEWSET_CONFIG)
    def test_user_created_successfully_when_email_has_a_valid_username(self):
        """
        Test that the user is created ok when
        username is not present in decoded token but email has a valid username
        """
        view = UserModelOpenIDConnectViewset.as_view({"post": "callback"})
        with patch(
            "oidc.viewsets.OpenIDClient.verify_and_decode_id_token"
        ) as mock_func:
            mock_func.return_value = {
                "family_name": "bob",
                "given_name": "just bob",
                "username": "boby@example.com",
                "email": "boby@example.com",
            }

            data = {"id_token": "sadsdaio3209lkasdlkas0d.sdojdsiad.iosdadia"}
            request = self.factory.post("/", data=data)
            response = view(request, auth_server="default")
            self.assertEqual(response.status_code, 302)
            user = User.objects.get(username="boby")
            self.assertEqual(user.email, "boby@example.com")

    @override_settings(OPENID_CONNECT_VIEWSET_CONFIG=OPENID_CONNECT_VIEWSET_CONFIG)
    def test_returns_data_entry_template_on_invalid_username(self):
        """
        Test that users are redirected to the data entry
        page when username is not present in decoded token and
        provided email also does not provide a valid username
        """
        view = UserModelOpenIDConnectViewset.as_view({"post": "callback"})
        with patch(
            "oidc.viewsets.OpenIDClient.verify_and_decode_id_token"
        ) as mock_func:
            mock_func.return_value = {
                "family_name": "bob",
                "given_name": "just bob",
                "email": "bo@example.com",
            }

            data = {"id_token": "sadsdaio3209lkasdlkas0d.sdojdsiad.iosdadia"}
            request = self.factory.post("/", data=data)
            response = view(request, auth_server="default")
            self.assertEqual(response.status_code, 200)
            self.assertEqual(response.template_name, "oidc/oidc_user_data_entry.html")

    @override_settings(OPENID_CONNECT_VIEWSET_CONFIG=OPENID_CONNECT_VIEWSET_CONFIG)
    def test_returns_data_entry_template_on_invalid_username_and_bad_email(self):
        """
        Test that users are redirected to the data entry
        page when username provided in decoded token is invalid and
        provided email also does not provide a valid username
        """
        view = UserModelOpenIDConnectViewset.as_view({"post": "callback"})
        with patch(
            "oidc.viewsets.OpenIDClient.verify_and_decode_id_token"
        ) as mock_func:
            mock_func.return_value = {
                "family_name": "bob",
                "given_name": "just bob",
                "username": "bob@example.com",
                "email": "bo@example.com",
            }

            data = {"id_token": "sadsdaio3209lkasdlkas0d.sdojdsiad.iosdadia"}
            request = self.factory.post("/", data=data)
            response = view(request, auth_server="default")
            self.assertEqual(response.status_code, 400)
            # Don't pin JSON key order — the helper that builds this
            # response merges in extra context keys (username_pattern,
            # username_help_text), so the error key may not be first.
            self.assertIn(
                b'"error":"Username should only contain word characters & numbers and should have 3 or more characters"',
                response.rendered_content,
            )
            self.assertEqual(response.template_name, "oidc/oidc_user_data_entry.html")

    def test_unrecoverable_error_on_missing_claim(self):
        """
        Test that an error is returned when a required claim field other than the
        username is missing from the ID Token
        """
        view = UserModelOpenIDConnectViewset.as_view({"post": "callback"})
        with patch(
            "oidc.viewsets.OpenIDClient.verify_and_decode_id_token"
        ) as mock_func:
            mock_func.return_value = {
                "username": "bob",
                "email": "bob@example.com",
            }

            data = {"id_token": "sadsdaio3209lkasdlkas0d.sdojdsiad.iosdadia"}
            request = self.factory.post("/", data=data)
            response = view(request, auth_server="default")
            self.assertEqual(response.status_code, 400)
            self.assertEqual(
                response.template_name, "oidc/oidc_unrecoverable_error.html"
            )
            self.assertEqual(
                response.data.get("error"), "Missing required fields: first_name"
            )

    def test_create_non_existing_user(self):
        """
        Test that a new user is created if the username is present and
        that the user is redirected to the `REDIRECT_AFTER_AUTH` link
        """
        view = UserModelOpenIDConnectViewset.as_view({"post": "callback"})
        with patch(
            "oidc.viewsets.OpenIDClient.verify_and_decode_id_token"
        ) as mock_func:
            mock_func.return_value = {
                "given_name": "john",
                "family_name": "doe",
                "email": "john@doe.com",
                "preferred_username": "john",
                "redirect_after_auth": "localhost/authenticate",
            }
            data = {"id_token": "saasdrrw.fdfdfdswg4gdfs.sadadsods"}
            user_count = User.objects.filter(username="john").count()
            request = self.factory.post("/", data=data)
            response = view(request, auth_server="default")
            self.assertEqual(
                user_count + 1, User.objects.filter(username="john").count()
            )
            # Redirects to the redirect url on successful user creation
            self.assertEqual(response.status_code, 302)
            self.assertEqual(response.url, "localhost/authenticate")

            # Uses last_name as first_name if missing
            mock_func.return_value = {
                "family_name": "davis",
                "email": "davis@justdavis.com",
                "preferred_username": "davis",
            }
            data = {
                "id_token": "sdadsadjaosd.sdadjiaodj.sdj91019d9",
            }
            user_count = User.objects.filter(username="davis").count()
            request = self.factory.post("/", data=data)
            response = view(request, auth_server="default")
            self.assertEqual(
                user_count + 1, User.objects.filter(username="john").count()
            )
            self.assertEqual(response.status_code, 302)
            user = User.objects.get(username="davis")
            self.assertEqual(user.first_name, "davis")

            # Returns a 400 response if both family_name and given_name
            # are missing
            mock_func.return_value = {
                "email": "jake@doe.com",
                "preferred_username": "jake",
            }
            data = {"id_token": "sdaodjadoaj9.sdoa09dj901.sd0h091"}
            request = self.factory.post("/", data=data)
            response = view(request, auth_server="default")
            self.assertEqual(response.status_code, 400)
            self.assertIn(
                "Missing required fields",
                response.rendered_content.decode("utf-8"),
            )

    def test_validates_data(self):
        """
        Test that the endpoint validates whether a username is already
        used within the system.

        i. Returns an error if same username is used
        ii. Returns an error if same username is used even if differently cased
        iii. Returns an error if value doesn't match regex
        """
        view = UserModelOpenIDConnectViewset.as_view({"post": "callback"})
        with patch(
            "oidc.viewsets.OpenIDClient.verify_and_decode_id_token"
        ) as mock_func:
            mock_func.return_value = {
                "given_name": "john",
                "family_name": "doe",
                "email": "john@doe.com",
                "preferred_username": "john",
            }
            data = {"id_token": "saasdrrw.fdfdfdswg4gdfs.sadadsods"}
            request = self.factory.post("/", data=data)
            response = view(request, auth_server="default")
            # Redirects to the redirect url on successful user creation
            self.assertEqual(response.status_code, 302)

            # Test returns an error if an existing username is used
            mock_func.return_value = {
                "given_name": "jane",
                "family_name": "doe",
                "email": "jane@doe.com",
                "preferred_username": "john",
            }
            data = {"id_token": "ssad9012.fdfdfdswg4gdfs.sadadsods"}
            user_count = User.objects.count()
            request = self.factory.post("/", data=data)
            response = view(request, auth_server="default")
            self.assertEqual(user_count, User.objects.count())
            self.assertEqual(response.status_code, 200)
            self.assertIn(
                "Username field is already in use.",
                response.rendered_content.decode("utf-8"),
            )

            # Test error still returned even if username is cased differently
            mock_func.return_value = {
                "given_name": "jane",
                "family_name": "doe",
                "email": "jane@doe.com",
                "preferred_username": "JoHn",
            }
            data = {"id_token": "ssad9012.fdfdfdswg4gdfs.sadadsods"}
            request = self.factory.post("/", data=data)
            response = view(request, auth_server="default")
            self.assertEqual(response.status_code, 200)
            self.assertIn(
                "Username field is already in use.",
                response.rendered_content.decode("utf-8"),
            )

            # Test error not returned if username is not in the ID Token
            mock_func.return_value = {
                "given_name": "jane",
                "family_name": "doe",
                "email": "jane@doe.com",
            }
            data = {"id_token": "ssad9012.fdfdfdswg4gdfs.sadadsods"}
            request = self.factory.post("/", data=data)
            response = view(request, auth_server="default")
            self.assertEqual(response.status_code, 200)
            self.assertNotIn(
                "Username field is already in use.",
                response.rendered_content.decode("utf-8"),
            )

            # Test error returned when username doesn't match regex
            mock_func.return_value = {
                "given_name": "jane",
                "family_name": "doe",
                "email": "jane@doe.com",
                "preferred_username": "12345",
            }
            data = {"id_token": "ssad9012.fdfdfdswg4gdfs.sadadsods"}
            request = self.factory.post("/", data=data)
            response = view(request, auth_server="default")
            self.assertEqual(response.status_code, 400)
            self.assertIn(
                "Username should only contain alpha numeric characters",
                response.rendered_content.decode("utf-8"),
            )

    @override_settings(OPENID_CONNECT_VIEWSET_CONFIG=OPENID_CONNECT_VIEWSET_CONFIG)
    def test_uses_first_part_of_email_as_username(self):
        """
        Test that when the USE_EMAIL_USERNAME setting is set to True
        the first part of the returned email address is used as a
        username
        """
        view = UserModelOpenIDConnectViewset.as_view({"post": "callback"})
        with patch(
            "oidc.viewsets.OpenIDClient.verify_and_decode_id_token"
        ) as mock_func:
            mock_func.return_value = {
                "family_name": "bob",
                "given_name": "just bob",
                "email": "bob@example.com",
            }

            data = {"id_token": "sadsdaio3209lkasdlkas0d.sdojdsiad.iosdadia"}
            count = User.objects.all().count()
            request = self.factory.post("/", data=data)
            response = view(request, auth_server="default")
            self.assertEqual(response.status_code, 302)
            self.assertEqual(count + 1, User.objects.all().count())
            self.assertEqual(1, User.objects.filter(username="bob").count())

        # Invalid characters are replaced
        with patch(
            "oidc.viewsets.OpenIDClient.verify_and_decode_id_token"
        ) as mock_func:
            mock_func.return_value = {
                "family_name": "jane",
                "given_name": "doe",
                "email": "jane.doe@example.com",
            }

            data = {"id_token": "sadsdaio3209lkasdlkas0d.sdojdsiad.iosdadia"}
            count = User.objects.all().count()
            request = self.factory.post("/", data=data)
            response = view(request, auth_server="default")
            self.assertEqual(response.status_code, 302)
            self.assertEqual(count + 1, User.objects.all().count())
            self.assertEqual(1, User.objects.filter(username="jane_doe").count())

        # Invalid characters that are not in the replacement list
        # cause the retrieved username to be ignored & returns the
        # user data entry form
        with patch(
            "oidc.viewsets.OpenIDClient.verify_and_decode_id_token"
        ) as mock_func:
            mock_func.return_value = {
                "family_name": "hello",
                "given_name": "jane",
                "email": "jane.doe+hello@example.com",
            }

            data = {"id_token": "sadsdaio3209lkasdlkas0d.sdojdsiad.iosdadia"}
            count = User.objects.all().count()
            request = self.factory.post("/", data=data)
            response = view(request, auth_server="default")
            self.assertEqual(response.status_code, 200)
            self.assertEqual(response.template_name, "oidc/oidc_user_data_entry.html")

    @override_settings(OPENID_CONNECT_AUTH_SERVERS=OPENID_CONNECT_AUTH_SERVERS)
    @patch(
        "oidc.viewsets.OpenIDClient.verify_and_decode_id_token",
        MagicMock(
            return_value={
                "given_name": "john",
                "family_name": "doe",
                "email": "john@doe.com",
                "preferred_username": "john",
            }
        ),
    )
    @patch("oidc.viewsets.OpenIDClient.retrieve_tokens_using_auth_code")
    def test_auth_code_flow(self, mock_retrieve_tokens_using_auth_code):
        """
        Test that the authorization code flow works as expected
        """
        mock_retrieve_tokens_using_auth_code.return_value = {
            "id_token": "ssad9012.fdfdfdswg4gdfs.sadadsods"
        }
        view = UserModelOpenIDConnectViewset.as_view({"post": "callback"})
        data = {"code": "SplxlOBeZQQYbYS6WxSbIA"}
        user_count = User.objects.filter(username="john").count()
        request = self.factory.post("/", data=data)
        response = view(request, auth_server="default")

        # Assert that the retrieve_tokens_using_auth_code function was called
        # and the code token was passed
        self.assertTrue(mock_retrieve_tokens_using_auth_code, True)
        self.assertEqual(
            mock_retrieve_tokens_using_auth_code.call_args[0][0], data["code"]
        )

        self.assertEqual(user_count + 1, User.objects.filter(username="john").count())
        # Redirects to the redirect url on successful user creation
        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.url, "http://localhost:3000")

    @override_settings(OPENID_CONNECT_AUTH_SERVERS=OPENID_CONNECT_AUTH_SERVERS)
    @override_settings(OPENID_CONNECT_VIEWSET_CONFIG=OPENID_CONNECT_VIEWSET_CONFIG)
    def test_base_open_id_connect_viewset(self):
        viewset_class = BaseOpenIDConnectViewset
        view = viewset_class.as_view({"get": "login"})
        request = self.factory.get("/")
        response = view(request, auth_server="default")
        # Verify that csrftoken cookie is deleted for the current domain
        self.assertIn("csrftoken", response.cookies)
        self.assertEqual(response.cookies["csrftoken"]["max-age"], 0)

    @override_settings(
        OPENID_CONNECT_AUTH_SERVERS={
            **OPENID_CONNECT_AUTH_SERVERS,
            "default": {
                **OPENID_CONNECT_AUTH_SERVERS["default"],
                "LOGIN_QUERY_PARAM_ALLOWLIST": [
                    "kc_idp_hint",
                    "prompt",
                    "login_hint",
                ],
            },
        },
        OPENID_CONNECT_VIEWSET_CONFIG=OPENID_CONNECT_VIEWSET_CONFIG,
    )
    def test_login_forwards_only_allowlisted_query_params(self):
        view = BaseOpenIDConnectViewset.as_view({"get": "login"})

        request = self.factory.get(
            "/?kc_idp_hint=github&prompt=login&login_hint=alice%40example.com"
            "&evil_param=injected"
        )
        response = view(request, auth_server="default")

        self.assertEqual(response.status_code, 302)
        self.assertIn("kc_idp_hint=github", response.url)
        self.assertIn("prompt=login", response.url)
        self.assertIn("login_hint=alice%40example.com", response.url)
        self.assertNotIn("evil_param", response.url)

    @override_settings(
        OPENID_CONNECT_AUTH_SERVERS=OPENID_CONNECT_AUTH_SERVERS,
        OPENID_CONNECT_VIEWSET_CONFIG=OPENID_CONNECT_VIEWSET_CONFIG,
    )
    def test_login_default_allowlist_drops_all_query_params(self):
        view = BaseOpenIDConnectViewset.as_view({"get": "login"})

        request = self.factory.get("/?kc_idp_hint=github&prompt=login")
        response = view(request, auth_server="default")

        self.assertEqual(response.status_code, 302)
        self.assertNotIn("kc_idp_hint", response.url)
        self.assertNotIn("prompt", response.url)

    @override_settings(
        OPENID_CONNECT_AUTH_SERVERS={
            **OPENID_CONNECT_AUTH_SERVERS,
            "default": {
                **OPENID_CONNECT_AUTH_SERVERS["default"],
                # ``next`` deliberately included in the allowlist to prove
                # the viewset's own exclusion overrides config.
                "LOGIN_QUERY_PARAM_ALLOWLIST": ["kc_idp_hint", "next"],
            },
        },
        OPENID_CONNECT_VIEWSET_CONFIG=OPENID_CONNECT_VIEWSET_CONFIG,
    )
    def test_login_consumes_next_does_not_forward_it(self):
        view = BaseOpenIDConnectViewset.as_view({"get": "login"})

        request = self.factory.get("/?next=/dashboard&kc_idp_hint=onadata")
        response = view(request, auth_server="default")

        self.assertEqual(response.status_code, 302)
        self.assertIn("kc_idp_hint=onadata", response.url)
        self.assertNotIn("next=", response.url)

    @override_settings(
        OPENID_CONNECT_AUTH_SERVERS=OPENID_CONNECT_AUTH_SERVERS,
        OPENID_CONNECT_VIEWSET_CONFIG=OPENID_CONNECT_VIEWSET_CONFIG,
    )
    def test_logout_forwards_id_token_hint_from_session(self):
        """The id_token stashed by the callback is threaded as
        ``id_token_hint`` on the end-session URL and popped from
        the session so it doesn't outlive the logout it served."""
        view = BaseOpenIDConnectViewset.as_view({"get": "logout"})

        request = self.factory.get("/")
        # Stand in for ``SessionMiddleware`` — APIRequestFactory skips it.
        request.session = {"oidc_id_token": "ey.signed.jwt", "unrelated": "keep"}
        response = view(request, auth_server="default")

        self.assertEqual(response.status_code, 302)
        self.assertEqual(
            response.url,
            "http://localhost:3000?id_token_hint=ey.signed.jwt",
        )
        # Pop, not get — the token must not outlive the session it served.
        self.assertNotIn("oidc_id_token", request.session)
        self.assertEqual(request.session.get("unrelated"), "keep")

    @override_settings(
        OPENID_CONNECT_AUTH_SERVERS={
            **OPENID_CONNECT_AUTH_SERVERS,
            "default": {
                **OPENID_CONNECT_AUTH_SERVERS["default"],
                "LOGOUT_QUERY_PARAM_ALLOWLIST": [
                    "logout_hint",
                    "ui_locales",
                ],
            },
        },
        OPENID_CONNECT_VIEWSET_CONFIG=OPENID_CONNECT_VIEWSET_CONFIG,
    )
    def test_logout_forwards_only_allowlisted_query_params(self):
        """Allowlisted query params flow through; everything else is
        dropped at the viewset boundary — same shape as login's
        ``LOGIN_QUERY_PARAM_ALLOWLIST``."""
        view = BaseOpenIDConnectViewset.as_view({"get": "logout"})

        request = self.factory.get(
            "/?logout_hint=alice%40example.com"
            "&ui_locales=en-GB"
            "&evil_param=injected"
        )
        request.session = {}
        response = view(request, auth_server="default")

        self.assertEqual(response.status_code, 302)
        self.assertIn("logout_hint=alice%40example.com", response.url)
        self.assertIn("ui_locales=en-GB", response.url)
        self.assertNotIn("evil_param", response.url)

    @override_settings(
        OPENID_CONNECT_AUTH_SERVERS={
            **OPENID_CONNECT_AUTH_SERVERS,
            "default": {
                **OPENID_CONNECT_AUTH_SERVERS["default"],
                # `id_token_hint` deliberately allowlisted to prove that
                # the server-stashed token wins over caller-supplied
                # query strings on collision.
                "LOGOUT_QUERY_PARAM_ALLOWLIST": ["id_token_hint"],
            },
        },
        OPENID_CONNECT_VIEWSET_CONFIG=OPENID_CONNECT_VIEWSET_CONFIG,
    )
    def test_logout_session_id_token_hint_wins_over_query_string(self):
        """If a caller smuggles ``id_token_hint`` via query string AND a
        legitimate token is stashed in the session, the trusted
        server-side value must take precedence."""
        view = BaseOpenIDConnectViewset.as_view({"get": "logout"})

        request = self.factory.get("/?id_token_hint=ey.attacker.jwt")
        request.session = {"oidc_id_token": "ey.legit.jwt"}
        response = view(request, auth_server="default")

        self.assertEqual(response.status_code, 302)
        self.assertIn("id_token_hint=ey.legit.jwt", response.url)
        self.assertNotIn("ey.attacker.jwt", response.url)

    @override_settings(
        OPENID_CONNECT_AUTH_SERVERS=OPENID_CONNECT_AUTH_SERVERS,
        OPENID_CONNECT_VIEWSET_CONFIG=OPENID_CONNECT_VIEWSET_CONFIG,
    )
    def test_logout_default_allowlist_drops_all_query_params(self):
        """No ``LOGOUT_QUERY_PARAM_ALLOWLIST`` configured → empty set →
        all query params dropped. Mirrors the login default."""
        view = BaseOpenIDConnectViewset.as_view({"get": "logout"})

        request = self.factory.get("/?logout_hint=alice&kc_idp_hint=onadata")
        request.session = {}
        response = view(request, auth_server="default")

        self.assertEqual(response.status_code, 302)
        # End-session URL untouched — bare endpoint, no stray `?`/`&`.
        self.assertEqual(response.url, "http://localhost:3000")

    @patch(
        "oidc.viewsets.OpenIDClient.verify_and_decode_id_token",
        MagicMock(
            return_value={
                "given_name": "john",
                "family_name": "doe",
                "email": "john@doe.com",
                "preferred_username": "john",
                "age": "unknown",
            }
        ),
    )
    @patch("oidc.viewsets.UserModelOpenIDConnectViewset.create_login_user")
    def test_only_creation_claims_passed(self, mock_func):
        """
        Test that only user creation fields are passed to the
        create_login_user function
        """
        expected_data = {
            "first_name": "john",
            "last_name": "doe",
            "email": "john@doe.com",
            "username": "john",
        }
        mock_func.return_value = User.objects.create(username="test")
        view = UserModelOpenIDConnectViewset.as_view({"post": "callback"})
        data = {"id_token": "saasdrrw.fdfdfdswg4gdfs.sadadsods"}
        request = self.factory.post("/", data=data)
        view(request, auth_server="default")
        self.assertTrue(mock_func.called)
        self.assertEqual(mock_func.call_args[0][0], expected_data)

    @override_settings(OPENID_CONNECT_VIEWSET_CONFIG=OPENID_CONNECT_VIEWSET_CONFIG)
    def test_map_claim_to_model(self):
        """
        Test that MAP_CLAIM_TO_MODEL maps sub to username and email.
        """
        view = UserModelOpenIDConnectViewset.as_view({"post": "callback"})
        with patch(
            "oidc.viewsets.OpenIDClient.verify_and_decode_id_token"
        ) as mock_func:
            mock_func.return_value = {
                "given_name": "john",
                "family_name": "doe",
                "sub": "john@doe.com",
                "name": "Avoided name",
            }
            user_count = User.objects.count()
            data = {"id_token": "saasdrrw.fdfdfdswg4gdfs.sadadsods"}
            request = self.factory.post("/", data=data)
            response = view(request, auth_server="default")
            # Redirects to the redirect url on successful user creation
            self.assertEqual(response.status_code, 302)
            user_count += 1
            self.assertEqual(User.objects.count(), user_count)
            # User attributes were set correctly
            # Ensure `name` claim was not used since the mapped first_name
            # & last_name were present
            user = User.objects.last()
            self.assertEqual(user.first_name, "john")
            self.assertEqual(user.last_name, "doe")
            self.assertEqual(user.email, "john@doe.com")

            mock_func.return_value = {
                "given_name": "john",
                "family_name": "doe",
                "sub": "john@doe.com",
            }
            data = {"id_token": "saasdrrw.fdfdfdswg4gdfs.sadadsods"}
            request = self.factory.post("/", data=data)
            response = view(request, auth_server="default")
            # Redirects to the redirect url on successful user creation
            self.assertEqual(response.status_code, 302)
            # There has been no change in number of User accounts
            self.assertEqual(User.objects.count(), user_count)

            # Name is split into first_name and last_name if both any is not
            # present
            mock_func.return_value = {
                "given_name": "Wrong",
                "name": "Davis Raym",
                "sub": "davis@m.com",
            }
            data = {"id_token": "saasdrrw.fdfdfdswg4gdfs.sadadsods"}
            request = self.factory.post("/", data=data)
            response = view(request, auth_server="default")
            self.assertEqual(response.status_code, 302)
            self.assertEqual(User.objects.count(), user_count + 1)
            # Ensure user attributes were set correctly
            user = User.objects.last()
            self.assertEqual(user.first_name, "Davis")
            self.assertEqual(user.last_name, "Raym")
            self.assertEqual(user.email, "davis@m.com")
            # Ensure default values are respected if not overriden
            self.assertEqual(user.is_active, False)

    @override_settings(OPENID_CONNECT_VIEWSET_CONFIG=OPENID_CONNECT_VIEWSET_CONFIG)
    def test_user_defaults_flows(self):
        """
        Test that different user defaults flows....
        """
        # Mock two ID Tokens
        view = UserModelOpenIDConnectViewset.as_view({"post": "callback"})
        with patch(
            "oidc.viewsets.OpenIDClient.verify_and_decode_id_token"
        ) as mock_func:
            mock_func.return_value = {
                "given_name": "john",
                "family_name": "doe",
                "sub": "john@ona.io",
                "name": "Avoided name",
            }
            user_count = User.objects.count()
            data = {"id_token": "saasdrrw.fdfdfdswg4gdfs.sadadsods"}
            request = self.factory.post("/", data=data)
            response = view(request, auth_server="default")
            # Redirects to the redirect url on successful user creation
            self.assertEqual(response.status_code, 302)
            user_count += 1
            self.assertEqual(User.objects.count(), user_count)
            # User attributes were set correctly
            # Ensure `name` claim was not used since the mapped first_name
            # & last_name were present
            user = User.objects.last()
            self.assertEqual(user.first_name, "john")
            self.assertEqual(user.last_name, "doe")
            self.assertEqual(user.email, "john@ona.io")
            self.assertEqual(user.username, "john")
            self.assertEqual(user.is_active, True)

            # User who aren't from @ona.io should have is_active set to False
            mock_func.return_value = {
                "given_name": "john",
                "family_name": "doe",
                "sub": "johne@example.com",
                "name": "Avoided name",
            }
            user_count = User.objects.count()
            request = self.factory.post("/", data=data)
            response = view(request, auth_server="default")
            # Redirects to the redirect url on successful user creation
            self.assertEqual(response.status_code, 302)
            user_count += 1
            self.assertEqual(User.objects.count(), user_count)
            # User attributes were set correctly
            # Ensure `name` claim was not used since the mapped first_name
            # & last_name were present
            user = User.objects.last()
            self.assertEqual(user.first_name, "john")
            self.assertEqual(user.last_name, "doe")
            self.assertEqual(user.username, "johne")
            self.assertEqual(user.email, "johne@example.com")
            self.assertEqual(user.is_active, False)

    @override_settings(OPENID_CONNECT_VIEWSET_CONFIG=OPENID_CONNECT_VIEWSET_CONFIG)
    def test_direct_access_to_callback_fails(self):
        """
        Test that requests to the callback endpoint without
        a valid session / login request fails gracefully
        """
        # Mock two ID Tokens
        view = UserModelOpenIDConnectViewset.as_view({"get": "callback"})
        request = self.factory.get("/oidc/default/callback", format="html")
        response = view(request, auth_server="default", format="html")
        self.assertEqual(response.status_code, 400)
        response.render()
        content = response.content.decode("utf-8")
        self.assertTrue(
            "Unable to process OpenID connect authentication request." in content
        )
        self.assertTrue("Something went wrong, please try again later" in content)

    @override_settings(OPENID_CONNECT_VIEWSET_CONFIG=OPENID_CONNECT_VIEWSET_CONFIG)
    def test_last_login_updated_on_successful_authentication(self):
        """
        Test that last_login is updated when an existing user successfully authenticates
        """
        # First create a user
        user = User.objects.create_user(
            username="testuser",
            email="testuser@example.com",
            first_name="Test",
            last_name="User",
        )
        original_last_login = user.last_login

        view = UserModelOpenIDConnectViewset.as_view({"post": "callback"})
        with patch(
            "oidc.viewsets.OpenIDClient.verify_and_decode_id_token"
        ) as mock_func:
            mock_func.return_value = {
                "given_name": "Test",
                "family_name": "User",
                "email": "testuser@example.com",
                "preferred_username": "testuser",
            }

            data = {"id_token": "test.token.here"}
            request = self.factory.post("/", data=data)

            # Mock timezone.now() to control the timestamp
            mock_timestamp = timezone.now()
            with patch("oidc.viewsets.timezone.now") as mock_now:
                mock_now.return_value = mock_timestamp

                response = view(request, auth_server="default")

                # Should redirect on successful authentication
                self.assertEqual(response.status_code, 302)

                # Verify user's last_login was updated
                user.refresh_from_db()
                self.assertEqual(user.last_login, mock_timestamp)
                self.assertNotEqual(user.last_login, original_last_login)

    @override_settings(OPENID_CONNECT_VIEWSET_CONFIG=OPENID_CONNECT_VIEWSET_CONFIG)
    def test_last_login_not_updated_on_new_user_creation(self):
        """
        Test that last_login is not explicitly set when creating a new user
        (Django's create_user handles this automatically)
        """
        view = UserModelOpenIDConnectViewset.as_view({"post": "callback"})
        with patch(
            "oidc.viewsets.OpenIDClient.verify_and_decode_id_token"
        ) as mock_func:
            mock_func.return_value = {
                "given_name": "New",
                "family_name": "User",
                "email": "newuser@example.com",
                "preferred_username": "newuser",
            }

            data = {"id_token": "test.token.here"}
            request = self.factory.post("/", data=data)

            # Mock timezone.now() to verify it's called for last_login update
            mock_timestamp = timezone.now()
            with patch("oidc.viewsets.timezone.now") as mock_now:
                mock_now.return_value = mock_timestamp

                response = view(request, auth_server="default")

                # Should redirect on successful user creation
                self.assertEqual(response.status_code, 302)

                # Verify new user was created
                user = User.objects.get(username="newuser")
                self.assertEqual(user.email, "newuser@example.com")

                # For new user creation, last_login should be set by Django
                # and the patch is called
                self.assertEqual(user.last_login, mock_timestamp)
                self.assertTrue(mock_now.called)

    @override_settings(OPENID_CONNECT_VIEWSET_CONFIG=OPENID_CONNECT_VIEWSET_CONFIG)
    def test_case_insensitive_email_matching_single_email(self):
        """
        Test that email matching is case-insensitive for single email lookup
        """
        user = User.objects.create_user(
            username="testuser",
            email="testuser@example.com",
            first_name="Test",
            last_name="User",
        )

        self.assertEqual(
            User.objects.filter(email__iexact="testuser@example.com").count(), 1
        )

        view = UserModelOpenIDConnectViewset.as_view({"post": "callback"})
        with patch(
            "oidc.viewsets.OpenIDClient.verify_and_decode_id_token"
        ) as mock_func:
            mock_func.return_value = {
                "given_name": "Test",
                "family_name": "User",
                "email": "TESTUSER@EXAMPLE.COM",
                "preferred_username": "testuser",
            }

            data = {"id_token": "test.token.here"}
            request = self.factory.post("/", data=data)
            response = view(request, auth_server="default")

            # Should successfully find existing user despite case difference
            self.assertEqual(response.status_code, 302)

            user.refresh_from_db()
            self.assertIsNotNone(user.last_login)

            self.assertEqual(
                User.objects.filter(email__iexact="testuser@example.com").count(), 1
            )

    @override_settings(OPENID_CONNECT_VIEWSET_CONFIG=OPENID_CONNECT_VIEWSET_CONFIG)
    def test_case_insensitive_email_matching_multiple_emails(self):
        """
        Test that email matching is case-insensitive when multiple emails are provided
        """
        user = User.objects.create_user(
            username="testuser2",
            email="testuser2@example.com",
            first_name="Test",
            last_name="User2",
        )

        self.assertEqual(
            User.objects.filter(email__iexact="testuser2@example.com").count(), 1
        )

        view = UserModelOpenIDConnectViewset.as_view({"post": "callback"})
        with patch(
            "oidc.viewsets.OpenIDClient.verify_and_decode_id_token"
        ) as mock_func:
            mock_func.return_value = {
                "given_name": "Test",
                "family_name": "User2",
                "emails": [
                    "NONEXISTENT@EXAMPLE.COM",
                    "TESTUSER2@EXAMPLE.COM",
                ],  # mixed case emails
                "preferred_username": "testuser2",
            }

            data = {"id_token": "test.token.here"}
            request = self.factory.post("/", data=data)
            response = view(request, auth_server="default")

            self.assertEqual(response.status_code, 302)

            user.refresh_from_db()
            self.assertIsNotNone(user.last_login)

            self.assertEqual(
                User.objects.filter(email__iexact="testuser2@example.com").count(), 1
            )

    @override_settings(
        OPENID_CONNECT_VIEWSET_CONFIG={
            **OPENID_CONNECT_VIEWSET_CONFIG,
            "SSO_COOKIE_DATA": "username",
        }
    )
    def test_disambiguates_shared_email_by_username(self):
        """
        When two accounts share an email, the callback attaches to the one
        whose username matches the ``preferred_username`` claim instead of
        raising MultipleObjectsReturned or picking an arbitrary account.
        """
        User.objects.create_user(
            username="john", email="team@example.com", first_name="John"
        )
        jane = User.objects.create_user(
            username="jane", email="team@example.com", first_name="Jane"
        )

        view = UserModelOpenIDConnectViewset.as_view({"post": "callback"})
        with patch(
            "oidc.viewsets.OpenIDClient.verify_and_decode_id_token"
        ) as mock_func:
            mock_func.return_value = {
                "given_name": "Jane",
                "family_name": "Doe",
                "email": "team@example.com",
                "preferred_username": "jane",
            }
            data = {"id_token": "test.token.here"}
            request = self.factory.post("/", data=data)
            response = view(request, auth_server="default")

        self.assertEqual(response.status_code, 302)
        # The matching account was logged in...
        jane.refresh_from_db()
        self.assertIsNotNone(jane.last_login)
        # ...and the other account sharing the email was left untouched.
        self.assertIsNone(User.objects.get(username="john").last_login)

    @override_settings(
        OPENID_CONNECT_VIEWSET_CONFIG={
            **OPENID_CONNECT_VIEWSET_CONFIG,
            "SSO_COOKIE_DATA": "username",
        }
    )
    def test_sso_cookie_payload_uses_configured_field(self):
        """The SSO cookie encodes the configured field as its claim key."""
        User.objects.create_user(
            username="patrick", email="patrick@example.com", first_name="Patrick"
        )

        view = UserModelOpenIDConnectViewset.as_view({"post": "callback"})
        with patch(
            "oidc.viewsets.OpenIDClient.verify_and_decode_id_token"
        ) as mock_func:
            mock_func.return_value = {
                "given_name": "Patrick",
                "family_name": "Doe",
                "email": "patrick@example.com",
                "preferred_username": "patrick",
            }
            data = {"id_token": "test.token.here"}
            request = self.factory.post("/", data=data)
            response = view(request, auth_server="default")

        self.assertEqual(response.status_code, 302)
        sso_cookie = response.cookies.get("SSO")
        self.assertIsNotNone(sso_cookie)
        payload = jwt.decode(sso_cookie.value, "abc", algorithms=["HS256"])
        self.assertEqual(payload, {"username": "patrick"})

    @override_settings(
        OPENID_CONNECT_VIEWSET_CONFIG=OPENID_CONNECT_VIEWSET_CONFIG,
        OPENID_CONNECT_AUTH_SERVERS=OPENID_CONNECT_AUTH_SERVERS,
    )
    @patch.object(OpenIDClient, "retrieve_tokens_using_auth_code")
    @patch.object(OpenIDClient, "verify_and_decode_id_token")
    def test_auth_code_pkce_flow_mode_form_post(
        self, mock_verify_and_decode_id_token, mock_retrieve_tokens_using_auth_code
    ):
        """Auth code + PKCE flow works as expected with form_post response mode"""
        mock_verify_and_decode_id_token.return_value = {
            "given_name": "john",
            "family_name": "doe",
            "email": "john@example.com",
            "preferred_username": "john",
        }
        mock_retrieve_tokens_using_auth_code.return_value = {"id_token": "id_token"}
        view = UserModelOpenIDConnectViewset.as_view({"post": "callback"})
        # Simulate the code verifier being in the cache, namespaced the
        # way client.login() writes it.
        state = "pkce_123"
        cache.set(state_cache_key(state), "123")

        data = {"state": state, "code": "auth_code"}
        request = self.factory.post("/", data=data)
        response = view(request, auth_server="pkce")

        self.assertEqual(response.status_code, 302)

        user = User.objects.get(username="john")
        self.assertEqual(user.email, "john@example.com")
        self.assertEqual(user.first_name, "john")
        self.assertEqual(user.last_name, "doe")
        mock_retrieve_tokens_using_auth_code.assert_called_once_with(
            "auth_code", code_verifier="123"
        )
        # Code verifier is removed from cache
        self.assertIsNone(cache.get(state_cache_key(state)))

    @override_settings(
        OPENID_CONNECT_VIEWSET_CONFIG=OPENID_CONNECT_VIEWSET_CONFIG,
        OPENID_CONNECT_AUTH_SERVERS={
            **OPENID_CONNECT_AUTH_SERVERS,
            "pkce": {
                **OPENID_CONNECT_AUTH_SERVERS["pkce"],
                "RESPONSE_MODE": "query",
            },
        },
    )
    @patch.object(OpenIDClient, "retrieve_tokens_using_auth_code")
    @patch.object(OpenIDClient, "verify_and_decode_id_token")
    def test_auth_code_pkce_flow_mode_query(
        self, mock_verify_and_decode_id_token, mock_retrieve_tokens_using_auth_code
    ):
        """Auth code + PKCE flow works as expected with query response mode"""
        mock_verify_and_decode_id_token.return_value = {
            "given_name": "john",
            "family_name": "doe",
            "email": "john@example.com",
            "preferred_username": "john",
        }
        mock_retrieve_tokens_using_auth_code.return_value = {"id_token": "id_token"}
        view = UserModelOpenIDConnectViewset.as_view({"get": "callback"})
        # Simulate the code verifier being in the cache, namespaced the
        # way client.login() writes it.
        state = "pkce_123"
        cache.set(state_cache_key(state), "123")

        data = {"state": state, "code": "auth_code"}
        request = self.factory.get("/", data=data)
        response = view(request, auth_server="pkce")
        self.assertEqual(response.status_code, 302)

        user = User.objects.get(username="john")
        self.assertEqual(user.email, "john@example.com")
        self.assertEqual(user.first_name, "john")
        self.assertEqual(user.last_name, "doe")
        mock_retrieve_tokens_using_auth_code.assert_called_once_with(
            "auth_code", code_verifier="123"
        )
        # Code verifier is removed from cache
        self.assertIsNone(cache.get(state_cache_key(state)))

    @override_settings(
        OPENID_CONNECT_VIEWSET_CONFIG=OPENID_CONNECT_VIEWSET_CONFIG,
        OPENID_CONNECT_AUTH_SERVERS=OPENID_CONNECT_AUTH_SERVERS,
    )
    def test_pkce_flow_code_verifier_not_found(self):
        """Missing code verifier in the cache should raise an error"""
        view = UserModelOpenIDConnectViewset.as_view({"post": "callback"})
        data = {"state": "pkce_123", "code": "auth_code"}
        request = self.factory.post("/", data=data)
        response = view(request, auth_server="pkce")
        self.assertEqual(response.status_code, 401)
        self.assertEqual(
            response.data["error"],
            (
                "Unable to validate authentication request; "
                "Kindly retry authentication process."
            ),
        )

    @override_settings(
        OPENID_CONNECT_VIEWSET_CONFIG=OPENID_CONNECT_VIEWSET_CONFIG,
        SESSION_COOKIE_SECURE=True,
    )
    @patch.object(jwt, "encode")
    @patch.object(OpenIDClient, "verify_and_decode_id_token")
    def test_cookie_set(
        self,
        mock_verify_and_decode_id_token,
        mock_encode,
    ):
        """Cookie is set correctly for SSO"""
        mock_verify_and_decode_id_token.return_value = {
            "given_name": "john",
            "family_name": "doe",
            "email": "john@example.com",
            "preferred_username": "john",
        }
        mock_encode.return_value = "jwt.token.here"
        view = UserModelOpenIDConnectViewset.as_view({"post": "callback"})
        data = {"id_token": "test.token.here"}
        request = self.factory.post("/", data=data)
        response = view(request, auth_server="default")
        self.assertEqual(response.status_code, 302)
        self.assertTrue(response.cookies.get("SSO"))
        self.assertEqual(response.cookies.get("SSO").value, "jwt.token.here")
        self.assertEqual(response.cookies.get("SSO")["httponly"], True)
        self.assertEqual(response.cookies.get("SSO")["secure"], True)
        self.assertEqual(response.cookies.get("SSO")["samesite"], "Lax")
        self.assertEqual(response.cookies.get("SSO")["path"], "/")
        self.assertEqual(response.cookies.get("SSO")["max-age"], 60 * 60 * 24 * 30)
        self.assertEqual(response.cookies.get("SSO")["domain"], ".example.com")

    @override_settings(
        OPENID_CONNECT_VIEWSET_CONFIG={
            **OPENID_CONNECT_VIEWSET_CONFIG,
            "AUTO_CREATE_USER": False,
        }
    )
    @patch.object(OpenIDClient, "verify_and_decode_id_token")
    def test_auto_create_user_disabled(self, mock_verify_and_decode_id_token):
        """New user is not created if auto create user is disabled"""
        mock_verify_and_decode_id_token.return_value = {
            "given_name": "john",
            "family_name": "doe",
            "email": "john@example.com",
            "preferred_username": "john",
        }
        view = UserModelOpenIDConnectViewset.as_view({"post": "callback"})
        data = {"id_token": "test.token.here"}
        request = self.factory.post("/", data=data)
        response = view(request, auth_server="default")
        self.assertEqual(response.status_code, 401)
        self.assertEqual(response.data["error_title"], "Request not authorized")
        self.assertEqual(
            response.data["error"],
            "The request is not authorized. Please contact the administrator.",
        )

    @override_settings(
        OPENID_CONNECT_VIEWSET_CONFIG={
            **OPENID_CONNECT_VIEWSET_CONFIG,
            "AUTO_CREATE_USER": False,
        },
        OPENID_CONNECT_AUTH_SERVERS=OPENID_CONNECT_AUTH_SERVERS,
    )
    @patch.object(OpenIDClient, "retrieve_tokens_using_auth_code")
    @patch.object(OpenIDClient, "verify_and_decode_id_token")
    def test_auto_create_user_disabled_state_cleared(
        self, mock_verify_and_decode_id_token, mock_retrieve_tokens_using_auth_code
    ):
        """Cached login state is cleared if auto create is false"""
        mock_verify_and_decode_id_token.return_value = {
            "given_name": "john",
            "family_name": "doe",
            "email": "john@example.com",
            "preferred_username": "john",
        }
        mock_retrieve_tokens_using_auth_code.return_value = {"id_token": "id_token"}

        # Simulate the cached code verifier (namespaced as client.login()
        # would write it).
        state = "pkce_123"
        cache.set(state_cache_key(state), "123")

        view = UserModelOpenIDConnectViewset.as_view({"post": "callback"})
        data = {"state": state, "code": "auth_code"}
        request = self.factory.post("/", data=data)
        response = view(request, auth_server="pkce")

        self.assertEqual(response.status_code, 401)
        self.assertEqual(response.data["error_title"], "Request not authorized")
        self.assertEqual(
            response.data["error"],
            "The request is not authorized. Please contact the administrator.",
        )
        self.assertIsNone(cache.get(state_cache_key(state)))

    def _callback_cookie(self, mock_verify, mock_encode):
        mock_verify.return_value = {
            "given_name": "john",
            "family_name": "doe",
            "email": "john@example.com",
            "preferred_username": "john",
        }
        mock_encode.return_value = "jwt.token.here"
        view = UserModelOpenIDConnectViewset.as_view({"post": "callback"})
        request = self.factory.post("/", data={"id_token": "test.token.here"})
        response = view(request, auth_server="default")
        self.assertEqual(response.status_code, 302)
        return response.cookies.get("SSO")

    @override_settings(
        OPENID_CONNECT_VIEWSET_CONFIG=OPENID_CONNECT_VIEWSET_CONFIG,
        SESSION_COOKIE_SECURE=True,
    )
    @patch.object(jwt, "encode")
    @patch.object(OpenIDClient, "verify_and_decode_id_token")
    def test_cookie_secure_default_from_session_secure(self, mock_verify, mock_encode):
        """Secure defaults to settings.SESSION_COOKIE_SECURE when unset."""
        cookie = self._callback_cookie(mock_verify, mock_encode)
        self.assertEqual(cookie["secure"], True)

    @override_settings(
        OPENID_CONNECT_VIEWSET_CONFIG=OPENID_CONNECT_VIEWSET_CONFIG,
    )
    @patch.object(jwt, "encode")
    @patch.object(OpenIDClient, "verify_and_decode_id_token")
    def test_cookie_secure_default_falls_back_to_false(self, mock_verify, mock_encode):
        """With SESSION_COOKIE_SECURE unset, Secure falls back to False."""
        cookie = self._callback_cookie(mock_verify, mock_encode)
        self.assertEqual(cookie["secure"], "")

    @override_settings(
        OPENID_CONNECT_VIEWSET_CONFIG={
            **OPENID_CONNECT_VIEWSET_CONFIG,
            "SSO_COOKIE_SECURE": True,
        },
        SESSION_COOKIE_SECURE=False,
    )
    @patch.object(jwt, "encode")
    @patch.object(OpenIDClient, "verify_and_decode_id_token")
    def test_cookie_secure_override_wins_true(self, mock_verify, mock_encode):
        """Explicit SSO_COOKIE_SECURE=True wins over SESSION_COOKIE_SECURE."""
        cookie = self._callback_cookie(mock_verify, mock_encode)
        self.assertEqual(cookie["secure"], True)

    @override_settings(
        OPENID_CONNECT_VIEWSET_CONFIG={
            **OPENID_CONNECT_VIEWSET_CONFIG,
            "SSO_COOKIE_SECURE": False,
        },
        SESSION_COOKIE_SECURE=True,
    )
    @patch.object(jwt, "encode")
    @patch.object(OpenIDClient, "verify_and_decode_id_token")
    def test_cookie_secure_override_wins_false(self, mock_verify, mock_encode):
        """Explicit SSO_COOKIE_SECURE=False wins over SESSION_COOKIE_SECURE."""
        cookie = self._callback_cookie(mock_verify, mock_encode)
        self.assertEqual(cookie["secure"], "")

    @override_settings(
        OPENID_CONNECT_VIEWSET_CONFIG={
            **OPENID_CONNECT_VIEWSET_CONFIG,
            "SSO_COOKIE_SAMESITE": "Strict",
        },
    )
    @patch.object(jwt, "encode")
    @patch.object(OpenIDClient, "verify_and_decode_id_token")
    def test_cookie_samesite_strict(self, mock_verify, mock_encode):
        cookie = self._callback_cookie(mock_verify, mock_encode)
        self.assertEqual(cookie["samesite"], "Strict")

    @override_settings(
        OPENID_CONNECT_VIEWSET_CONFIG={
            **OPENID_CONNECT_VIEWSET_CONFIG,
            "SSO_COOKIE_SAMESITE": "None",
            "SSO_COOKIE_SECURE": True,
        },
    )
    @patch.object(jwt, "encode")
    @patch.object(OpenIDClient, "verify_and_decode_id_token")
    def test_cookie_samesite_none_with_secure(self, mock_verify, mock_encode):
        cookie = self._callback_cookie(mock_verify, mock_encode)
        self.assertEqual(cookie["samesite"], "None")
        self.assertEqual(cookie["secure"], True)

    @override_settings(
        OPENID_CONNECT_VIEWSET_CONFIG={
            **OPENID_CONNECT_VIEWSET_CONFIG,
            "SSO_COOKIE_SAMESITE": "None",
            "SSO_COOKIE_SECURE": False,
        },
    )
    def test_cookie_samesite_none_without_secure_raises(self):
        """SameSite=None + Secure=False must raise at viewset construction."""
        with self.assertRaises(ImproperlyConfigured):
            UserModelOpenIDConnectViewset()

    @override_settings(
        OPENID_CONNECT_VIEWSET_CONFIG={
            **OPENID_CONNECT_VIEWSET_CONFIG,
            "SSO_COOKIE_HTTPONLY": False,
        },
    )
    @patch.object(jwt, "encode")
    @patch.object(OpenIDClient, "verify_and_decode_id_token")
    def test_cookie_httponly_false(self, mock_verify, mock_encode):
        cookie = self._callback_cookie(mock_verify, mock_encode)
        self.assertEqual(cookie["httponly"], "")

    @override_settings(
        OPENID_CONNECT_VIEWSET_CONFIG={
            **OPENID_CONNECT_VIEWSET_CONFIG,
            "SSO_COOKIE_PATH": "/app",
        },
    )
    @patch.object(jwt, "encode")
    @patch.object(OpenIDClient, "verify_and_decode_id_token")
    def test_cookie_path_custom(self, mock_verify, mock_encode):
        cookie = self._callback_cookie(mock_verify, mock_encode)
        self.assertEqual(cookie["path"], "/app")

    @override_settings(
        OPENID_CONNECT_VIEWSET_CONFIG={
            **OPENID_CONNECT_VIEWSET_CONFIG,
            "USE_SSO_COOKIE": True,
            "SSO_COOKIE_PATH": "/app",
            "SSO_COOKIE_SAMESITE": "Strict",
        },
        OPENID_CONNECT_AUTH_SERVERS=OPENID_CONNECT_AUTH_SERVERS,
    )
    def test_logout_delete_matches_set_attributes(self):
        """Logout's delete_cookie must carry matching domain/path/samesite."""
        view = UserModelOpenIDConnectViewset.as_view({"get": "logout"})
        request = self.factory.get("/")
        response = view(request, auth_server="default")
        cookie = response.cookies.get("SSO")
        self.assertIsNotNone(cookie)
        self.assertEqual(cookie["domain"], ".example.com")
        self.assertEqual(cookie["path"], "/app")
        self.assertEqual(cookie["samesite"], "Strict")
        self.assertEqual(cookie["max-age"], 0)

    @override_settings(
        OPENID_CONNECT_VIEWSET_CONFIG=OPENID_CONNECT_VIEWSET_CONFIG,
        OPENID_CONNECT_AUTH_SERVERS=OPENID_CONNECT_AUTH_SERVERS,
        CSRF_COOKIE_DOMAIN=".example.com",
        CSRF_COOKIE_PATH="/admin",
        CSRF_COOKIE_SAMESITE="Strict",
    )
    def test_login_csrf_delete_honours_csrf_cookie_settings(self):
        """Login's csrftoken delete must carry matching CSRF_COOKIE_* attrs."""
        view = UserModelOpenIDConnectViewset.as_view({"get": "login"})
        request = self.factory.get("/")
        response = view(request, auth_server="default")
        cookie = response.cookies.get("csrftoken")
        self.assertIsNotNone(cookie)
        self.assertEqual(cookie["domain"], ".example.com")
        self.assertEqual(cookie["path"], "/admin")
        self.assertEqual(cookie["samesite"], "Strict")
        self.assertEqual(cookie["max-age"], 0)


class TestLoginNextValidation(TestCase):
    def setUp(self):
        self.factory = APIRequestFactory()

    @override_settings(
        OPENID_CONNECT_AUTH_SERVERS=OPENID_CONNECT_AUTH_SERVERS,
        OPENID_CONNECT_VIEWSET_CONFIG=OPENID_CONNECT_VIEWSET_CONFIG,
    )
    @patch("oidc.client.cache.set")
    def test_safe_relative_next_is_cached(self, mock_cache_set):
        view = BaseOpenIDConnectViewset.as_view({"get": "login"})
        view(self.factory.get("/?next=/dashboard"), auth_server="default")
        cached_payload = mock_cache_set.call_args[0][1]
        self.assertEqual(cached_payload["redirect_after"], "/dashboard")

    @override_settings(
        OPENID_CONNECT_AUTH_SERVERS={
            **OPENID_CONNECT_AUTH_SERVERS,
            "default": {
                **OPENID_CONNECT_AUTH_SERVERS["default"],
                "USE_NONCES": True,
            },
        },
        OPENID_CONNECT_VIEWSET_CONFIG=OPENID_CONNECT_VIEWSET_CONFIG,
    )
    @patch("oidc.client.cache.set")
    def test_unsafe_external_next_is_dropped(self, mock_cache_set):
        view = BaseOpenIDConnectViewset.as_view({"get": "login"})
        view(
            self.factory.get("/?next=https://attacker.example/phish"),
            auth_server="default",
        )
        cached_payload = mock_cache_set.call_args[0][1]
        self.assertIsNone(cached_payload["redirect_after"])

    @override_settings(
        OPENID_CONNECT_AUTH_SERVERS={
            **OPENID_CONNECT_AUTH_SERVERS,
            "default": {
                **OPENID_CONNECT_AUTH_SERVERS["default"],
                "LOGIN_REDIRECT_ALLOWED_HOSTS": ["spa.example.com"],
            },
        },
        OPENID_CONNECT_VIEWSET_CONFIG=OPENID_CONNECT_VIEWSET_CONFIG,
    )
    @patch("oidc.client.cache.set")
    def test_allowlisted_cross_origin_next_is_cached(self, mock_cache_set):
        view = BaseOpenIDConnectViewset.as_view({"get": "login"})
        view(
            self.factory.get("/?next=https://spa.example.com/dashboard"),
            auth_server="default",
        )
        cached_payload = mock_cache_set.call_args[0][1]
        self.assertEqual(
            cached_payload["redirect_after"], "https://spa.example.com/dashboard"
        )


class TestPerProviderTargetUrlAfterAuth(TestCase):
    """
    Pin the post-auth landing URL resolution order in
    generate_successful_response:
      1. explicit redirect_after (per-request, from id_token claim)
      2. per-provider TARGET_URL_AFTER_AUTH on
         OPENID_CONNECT_AUTH_SERVERS[auth_server]
      3. global REDIRECT_AFTER_AUTH on OPENID_CONNECT_VIEWSET_CONFIG

    Lets multi-tenant deployments give each provider its own landing
    page without mutating a shared global default that would break
    other tenants on the same install.
    """

    def setUp(self):
        TestCase().setUp()
        self.factory = APIRequestFactory()
        cache.clear()

    def _post_callback(self, *, id_token_claims, auth_server):
        view = UserModelOpenIDConnectViewset.as_view({"post": "callback"})
        with patch(
            "oidc.viewsets.OpenIDClient.verify_and_decode_id_token"
        ) as mock_func:
            mock_func.return_value = id_token_claims
            request = self.factory.post(
                "/",
                data={"id_token": "header.payload.signature"},
            )
            return view(request, auth_server=auth_server)

    @override_settings(
        OPENID_CONNECT_AUTH_SERVERS={
            "primary": {
                "AUTHORIZATION_ENDPOINT": "https://example.com/authorize",
                "CLIENT_ID": "client",
                "JWKS_ENDPOINT": "https://example.com/keys",
                "SCOPE": "openid profile email",
                "TOKEN_ENDPOINT": "https://example.com/token",
                "END_SESSION_ENDPOINT": "https://example.com/logout",
                "REDIRECT_URI": "http://localhost:8000/oidc/primary/callback",
                "RESPONSE_TYPE": "id_token",
                "RESPONSE_MODE": "form_post",
                "USE_NONCES": False,
                "USE_EMAIL_USERNAME": True,
                "TARGET_URL_AFTER_AUTH": "https://primary.example.com/landing",
            },
        },
        OPENID_CONNECT_VIEWSET_CONFIG={
            "REDIRECT_AFTER_AUTH": "https://global-default.example.com",
            "USE_SSO_COOKIE": False,
            "JWT_SECRET_KEY": "secret",
            "JWT_ALGORITHM": "HS256",
        },
    )
    def test_per_provider_target_wins_over_global_default(self):
        response = self._post_callback(
            id_token_claims={
                "given_name": "ada",
                "family_name": "lovelace",
                "email": "ada1@example.com",
                "preferred_username": "ada1",
            },
            auth_server="primary",
        )
        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.url, "https://primary.example.com/landing")

    @override_settings(
        OPENID_CONNECT_AUTH_SERVERS={
            "primary": {
                "AUTHORIZATION_ENDPOINT": "https://example.com/authorize",
                "CLIENT_ID": "client",
                "JWKS_ENDPOINT": "https://example.com/keys",
                "SCOPE": "openid profile email",
                "TOKEN_ENDPOINT": "https://example.com/token",
                "END_SESSION_ENDPOINT": "https://example.com/logout",
                "REDIRECT_URI": "http://localhost:8000/oidc/primary/callback",
                "RESPONSE_TYPE": "id_token",
                "RESPONSE_MODE": "form_post",
                "USE_NONCES": False,
                "USE_EMAIL_USERNAME": True,
                "TARGET_URL_AFTER_AUTH": "https://primary.example.com/landing",
            },
        },
        OPENID_CONNECT_VIEWSET_CONFIG={
            "REDIRECT_AFTER_AUTH": "https://global-default.example.com",
            "USE_SSO_COOKIE": False,
            "JWT_SECRET_KEY": "secret",
            "JWT_ALGORITHM": "HS256",
        },
    )
    def test_explicit_redirect_after_claim_wins_over_per_provider(self):
        response = self._post_callback(
            id_token_claims={
                "given_name": "ada",
                "family_name": "lovelace",
                "email": "ada2@example.com",
                "preferred_username": "ada2",
                "redirect_after_auth": "https://requested.example.com/dashboard",
            },
            auth_server="primary",
        )
        self.assertEqual(response.status_code, 302)
        self.assertEqual(
            response.url, "https://requested.example.com/dashboard"
        )

    @override_settings(
        OPENID_CONNECT_AUTH_SERVERS={
            "primary": {
                "AUTHORIZATION_ENDPOINT": "https://example.com/authorize",
                "CLIENT_ID": "client",
                "JWKS_ENDPOINT": "https://example.com/keys",
                "SCOPE": "openid profile email",
                "TOKEN_ENDPOINT": "https://example.com/token",
                "END_SESSION_ENDPOINT": "https://example.com/logout",
                "REDIRECT_URI": "http://localhost:8000/oidc/primary/callback",
                "RESPONSE_TYPE": "id_token",
                "RESPONSE_MODE": "form_post",
                "USE_NONCES": False,
                "USE_EMAIL_USERNAME": True,
            },
        },
        OPENID_CONNECT_VIEWSET_CONFIG={
            "REDIRECT_AFTER_AUTH": "https://global-default.example.com",
            "USE_SSO_COOKIE": False,
            "JWT_SECRET_KEY": "secret",
            "JWT_ALGORITHM": "HS256",
        },
    )
    def test_global_default_applies_when_no_per_provider_target(self):
        response = self._post_callback(
            id_token_claims={
                "given_name": "ada",
                "family_name": "lovelace",
                "email": "ada3@example.com",
                "preferred_username": "ada3",
            },
            auth_server="primary",
        )
        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.url, "https://global-default.example.com")

    @override_settings(
        OPENID_CONNECT_AUTH_SERVERS={
            "primary": {
                "AUTHORIZATION_ENDPOINT": "https://example.com/authorize",
                "CLIENT_ID": "client",
                "JWKS_ENDPOINT": "https://example.com/keys",
                "SCOPE": "openid profile email",
                "TOKEN_ENDPOINT": "https://example.com/token",
                "END_SESSION_ENDPOINT": "https://example.com/logout",
                "REDIRECT_URI": "http://localhost:8000/oidc/primary/callback",
                "RESPONSE_TYPE": "id_token",
                "RESPONSE_MODE": "form_post",
                "USE_NONCES": False,
                "USE_EMAIL_USERNAME": True,
                "TARGET_URL_AFTER_AUTH": "https://primary.example.com/landing",
            },
            "secondary": {
                "AUTHORIZATION_ENDPOINT": "https://example.com/authorize",
                "CLIENT_ID": "client",
                "JWKS_ENDPOINT": "https://example.com/keys",
                "SCOPE": "openid profile email",
                "TOKEN_ENDPOINT": "https://example.com/token",
                "END_SESSION_ENDPOINT": "https://example.com/logout",
                "REDIRECT_URI": "http://localhost:8000/oidc/secondary/callback",
                "RESPONSE_TYPE": "id_token",
                "RESPONSE_MODE": "form_post",
                "USE_NONCES": False,
                "USE_EMAIL_USERNAME": True,
                "TARGET_URL_AFTER_AUTH": "https://secondary.example.com",
            },
        },
        OPENID_CONNECT_VIEWSET_CONFIG={
            "REDIRECT_AFTER_AUTH": "https://global-default.example.com",
            "USE_SSO_COOKIE": False,
            "JWT_SECRET_KEY": "secret",
            "JWT_ALGORITHM": "HS256",
        },
    )
    def test_two_providers_resolve_independent_targets(self):
        primary_response = self._post_callback(
            id_token_claims={
                "given_name": "ada",
                "family_name": "lovelace",
                "email": "ada4@example.com",
                "preferred_username": "ada4",
            },
            auth_server="primary",
        )
        secondary_response = self._post_callback(
            id_token_claims={
                "given_name": "grace",
                "family_name": "hopper",
                "email": "grace4@example.com",
                "preferred_username": "grace4",
            },
            auth_server="secondary",
        )
        self.assertEqual(primary_response.status_code, 302)
        self.assertEqual(primary_response.url, "https://primary.example.com/landing")
        self.assertEqual(secondary_response.status_code, 302)
        self.assertEqual(secondary_response.url, "https://secondary.example.com")
