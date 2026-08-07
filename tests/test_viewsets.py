"""
Tests for the OpenID Client
"""

import json
import logging
from types import SimpleNamespace

from django.contrib.auth import get_user_model
from django.core.cache import cache
from django.core.exceptions import ImproperlyConfigured
from django.test import TestCase
from django.test.utils import override_settings
from django.urls import Resolver404, get_resolver, resolve
from django.utils import timezone

import jwt
import requests
from mock import MagicMock, patch
from rest_framework.test import APIRequestFactory

from oidc.checks import check_session_backend_can_hold_tokens
from oidc.client import OpenIDClient, TokenVerificationFailed, state_cache_key
from oidc.keycloak import KeycloakOpenIDConnectViewset
from oidc.permissions import IsCsrfSafeAccountRequest, get_account_request_header
from oidc.urls import get_viewset_class
from oidc.utils import (
    ACCESS_TOKEN_SESSION_KEY,
    ID_TOKEN_SESSION_KEY,
    REFRESH_TOKEN_SESSION_KEY,
    pending_token_session_key,
    token_session_key,
)
from tests.project_viewsets import InjectedViewset
from oidc.viewsets import (
    DEFAULT_USERNAME_HELP_TEXT,
    DEFAULT_USERNAME_PATTERN,
    USERNAME_FORM_MARKER_FIELD,
    USERNAME_FORM_MARKER_VALUE,
    BaseOpenIDConnectViewset,
    RapidProOpenIDConnectViewset,
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
        request.session = {
            "oidc_id_token:default": "ey.signed.jwt",
            "unrelated": "keep",
        }
        response = view(request, auth_server="default")

        self.assertEqual(response.status_code, 302)
        self.assertEqual(
            response.url,
            "http://localhost:3000?id_token_hint=ey.signed.jwt",
        )
        # Pop, not get — the token must not outlive the session it served.
        self.assertNotIn("oidc_id_token:default", request.session)
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
        request.session = {"oidc_id_token:default": "ey.legit.jwt"}
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

    @override_settings(
        OPENID_CONNECT_AUTH_SERVERS={
            **OPENID_CONNECT_AUTH_SERVERS,
            "default": {
                **OPENID_CONNECT_AUTH_SERVERS["default"],
                "ACCOUNT_ENDPOINT": "https://idp.example.com/realms/r/account",
            },
        },
        OPENID_CONNECT_VIEWSET_CONFIG=OPENID_CONNECT_VIEWSET_CONFIG,
    )
    def test_account_proxy_no_session_token_returns_401(self):
        """No stashed access_token → 401, never reach Keycloak."""
        view = KeycloakOpenIDConnectViewset.as_view({"get": "linked_list"})

        request = self.factory.get("/")
        request.session = {}
        with patch("oidc.client.requests.request") as mock_request:
            response = view(request, auth_server="default")

        self.assertEqual(response.status_code, 401)
        # Critical: we never reached out to Keycloak.
        mock_request.assert_not_called()

    @override_settings(
        OPENID_CONNECT_AUTH_SERVERS={
            **OPENID_CONNECT_AUTH_SERVERS,
            "default": {
                **OPENID_CONNECT_AUTH_SERVERS["default"],
                "ACCOUNT_ENDPOINT": "https://idp.example.com/realms/r/account",
            },
        },
        OPENID_CONNECT_VIEWSET_CONFIG=OPENID_CONNECT_VIEWSET_CONFIG,
    )
    def test_account_proxy_refresh_rejected_by_idp_returns_401(self):
        """The IdP answered and refused the refresh token: the session really
        is dead, so signing in again is the right instruction."""
        view = KeycloakOpenIDConnectViewset.as_view({"get": "linked_list"})
        request = self.factory.get("/")
        request.session = {
            "oidc_access_token:default": "expired.access.token",
            "oidc_refresh_token:default": "revoked.refresh.token",
        }

        first_call = MagicMock(status_code=401, content=b"{}")
        first_call.json.return_value = {"error": "invalid_token"}
        refresh_call = MagicMock(status_code=400)
        refresh_call.raise_for_status.side_effect = requests.HTTPError("400")

        with (
            patch("oidc.client.requests.request", return_value=first_call),
            patch("oidc.client.requests.post", return_value=refresh_call),
        ):
            response = view(request, auth_server="default")

        self.assertEqual(response.status_code, 401)

    @override_settings(
        OPENID_CONNECT_AUTH_SERVERS={
            **OPENID_CONNECT_AUTH_SERVERS,
            "default": {
                **OPENID_CONNECT_AUTH_SERVERS["default"],
                "ACCOUNT_ENDPOINT": "https://idp.example.com/realms/r/account",
            },
        },
        OPENID_CONNECT_VIEWSET_CONFIG=OPENID_CONNECT_VIEWSET_CONFIG,
    )
    def test_account_proxy_refresh_transport_failure_returns_502(self):
        """Pin: an unreachable IdP must not be reported as an expired session.
        Doing so sends the user through a re-login that cannot fix a server
        problem."""
        view = KeycloakOpenIDConnectViewset.as_view({"get": "linked_list"})
        request = self.factory.get("/")
        request.session = {
            "oidc_access_token:default": "expired.access.token",
            "oidc_refresh_token:default": "stashed.refresh.token",
        }

        first_call = MagicMock(status_code=401, content=b"{}")
        first_call.json.return_value = {"error": "invalid_token"}

        with (
            patch("oidc.client.requests.request", return_value=first_call),
            patch(
                "oidc.client.requests.post",
                side_effect=requests.ConnectionError("idp unreachable"),
            ),
        ):
            response = view(request, auth_server="default")

        self.assertEqual(response.status_code, 502)

    @override_settings(
        OPENID_CONNECT_AUTH_SERVERS={
            **OPENID_CONNECT_AUTH_SERVERS,
            "default": {
                **OPENID_CONNECT_AUTH_SERVERS["default"],
                "ACCOUNT_ENDPOINT": "https://idp.example.com/realms/r/account",
            },
        },
        OPENID_CONNECT_VIEWSET_CONFIG=OPENID_CONNECT_VIEWSET_CONFIG,
    )
    def test_proxy_does_not_disguise_our_own_bugs_as_upstream_failures(self):
        """Pin: only transport/config errors become 502. A defect in our own
        response handling must surface as a 500 with a traceback, not as
        'could not reach the identity provider' pointing at Keycloak."""
        view = KeycloakOpenIDConnectViewset.as_view({"get": "credentials_list"})
        request = self.factory.get("/")
        request.session = {"oidc_access_token:default": "t"}

        with patch.object(
            KeycloakOpenIDConnectViewset,
            "_keycloak_account_request",
            side_effect=KeyError("bug in transform"),
        ):
            with self.assertRaises(KeyError):
                view(request, auth_server="default")

    @override_settings(
        OPENID_CONNECT_AUTH_SERVERS={
            **OPENID_CONNECT_AUTH_SERVERS,
            "default": {
                **OPENID_CONNECT_AUTH_SERVERS["default"],
                "ACCOUNT_ENDPOINT": "https://idp.example.com/realms/r/account",
            },
        },
        OPENID_CONNECT_VIEWSET_CONFIG=OPENID_CONNECT_VIEWSET_CONFIG,
    )
    def test_account_proxy_refreshes_on_401_and_retries(self):
        """Keycloak 401 → refresh access_token via refresh_token → retry.
        Session writeback so the next request uses the fresh token."""
        view = KeycloakOpenIDConnectViewset.as_view({"get": "linked_list"})

        request = self.factory.get("/")
        request.session = {
            "oidc_access_token:default": "expired.access.token",
            "oidc_refresh_token:default": "stashed.refresh.token",
        }

        first_call = MagicMock(status_code=401, content=b"{}")
        first_call.json.return_value = {"error": "invalid_token"}
        refresh_call = MagicMock(status_code=200)
        refresh_call.json.return_value = {
            "access_token": "fresh.access.token",
            "refresh_token": "fresh.refresh.token",
        }
        refresh_call.raise_for_status = MagicMock()
        second_call = MagicMock(status_code=200, content=b"[]")
        second_call.json.return_value = []

        with (
            patch(
                "oidc.client.requests.request",
                side_effect=[first_call, second_call],
            ) as mock_request,
            patch("oidc.client.requests.post", return_value=refresh_call) as mock_post,
        ):
            response = view(request, auth_server="default")

        self.assertEqual(response.status_code, 200)
        # Two account calls (GET 401 → GET 200) plus one token refresh
        # POST against ``token_endpoint``.
        self.assertEqual(mock_request.call_count, 2)
        self.assertEqual(mock_post.call_count, 1)
        # Retry used the fresh token.
        _args, kwargs = mock_request.call_args_list[1]
        self.assertEqual(
            kwargs["headers"]["Authorization"], "Bearer fresh.access.token"
        )
        # Session was updated with the fresh tokens.
        self.assertEqual(
            request.session["oidc_access_token:default"], "fresh.access.token"
        )
        self.assertEqual(
            request.session["oidc_refresh_token:default"], "fresh.refresh.token"
        )

    @override_settings(
        OPENID_CONNECT_AUTH_SERVERS=OPENID_CONNECT_AUTH_SERVERS,
        OPENID_CONNECT_VIEWSET_CONFIG=OPENID_CONNECT_VIEWSET_CONFIG,
    )
    def test_account_proxy_returns_503_when_endpoint_not_configured(self):
        """Deployments that haven't wired ``ACCOUNT_ENDPOINT`` get a
        clear 503 — never reach Keycloak with a half-baked URL."""
        view = KeycloakOpenIDConnectViewset.as_view({"get": "linked_list"})

        request = self.factory.get("/")
        request.session = {"oidc_access_token:default": "stashed.access.token"}

        with patch("oidc.client.requests.post") as mock_post:
            response = view(request, auth_server="default")

        self.assertEqual(response.status_code, 503)
        mock_post.assert_not_called()

    @override_settings(
        OPENID_CONNECT_AUTH_SERVERS={
            **OPENID_CONNECT_AUTH_SERVERS,
            "default": {
                **OPENID_CONNECT_AUTH_SERVERS["default"],
                "ACCOUNT_ENDPOINT": "https://idp.example.com/realms/r/account",
            },
        },
        OPENID_CONNECT_VIEWSET_CONFIG=OPENID_CONNECT_VIEWSET_CONFIG,
    )
    def test_keycloak_account_request_get_passes_through_status_and_body(self):
        """Shared helper round-trips method/path/body and surfaces upstream
        (status, body). Refresh + retry exists already; this locks the
        plain happy-path so the helper extraction is observably safe."""
        viewset = KeycloakOpenIDConnectViewset()
        client = OpenIDClient("default")
        session = {"oidc_access_token:default": "stashed.access.token"}

        upstream = MagicMock(status_code=200, content=b'{"hello":"world"}')
        upstream.json.return_value = {"hello": "world"}
        with patch(
            "oidc.client.requests.request", return_value=upstream
        ) as mock_request:
            status, body = viewset._keycloak_account_request(
                client, session, "GET", "/sessions/devices"
            )

        self.assertEqual(status, 200)
        self.assertEqual(body, {"hello": "world"})
        args, kwargs = mock_request.call_args
        self.assertEqual(args[0], "GET")
        self.assertEqual(
            args[1],
            "https://idp.example.com/realms/r/account/sessions/devices",
        )
        self.assertEqual(
            kwargs["headers"]["Authorization"], "Bearer stashed.access.token"
        )

    @override_settings(
        OPENID_CONNECT_AUTH_SERVERS={
            **OPENID_CONNECT_AUTH_SERVERS,
            "default": {
                **OPENID_CONNECT_AUTH_SERVERS["default"],
                "ACCOUNT_ENDPOINT": "https://idp.example.com/realms/r/account",
            },
        },
        OPENID_CONNECT_VIEWSET_CONFIG=OPENID_CONNECT_VIEWSET_CONFIG,
    )
    def test_sessions_list_flattens_devices_into_rows(self):
        """Keycloak returns DeviceRepresentation[] with nested sessions[].
        Proxy flattens to a per-session list so the SPA renders rows,
        not nested device groups. NOTE: ``browser`` lives on each nested
        session, while ``os`` is on the device — so the flattened row's
        browser must come from the session, not the device."""
        view = KeycloakOpenIDConnectViewset.as_view({"get": "sessions_list"})
        request = self.factory.get("/")
        request.session = {"oidc_access_token:default": "stashed.access.token"}

        upstream = MagicMock(status_code=200)
        upstream.content = b"[...]"
        upstream.json.return_value = [
            {
                "os": "macOS",
                "current": True,
                "sessions": [
                    {
                        "id": "sess-1",
                        "browser": "Chrome",
                        "ipAddress": "1.2.3.4",
                        "started": 1715520000,
                        "lastAccess": 1715526000,
                        "current": True,
                        "clients": [{"clientId": "example"}],
                    }
                ],
            },
            {
                "os": "Windows",
                "current": False,
                "sessions": [
                    {
                        "id": "sess-2",
                        "browser": "Firefox",
                        "ipAddress": "5.6.7.8",
                        "started": 1715500000,
                        "lastAccess": 1715505000,
                        "current": False,
                        "clients": [{"clientId": "example"}],
                    }
                ],
            },
        ]
        with patch("oidc.client.requests.request", return_value=upstream):
            response = view(request, auth_server="default")

        self.assertEqual(response.status_code, 200)
        rows = response.data
        self.assertEqual(len(rows), 2)
        self.assertEqual(rows[0]["id"], "sess-1")
        self.assertEqual(rows[0]["browser"], "Chrome")
        self.assertEqual(rows[0]["os"], "macOS")
        self.assertTrue(rows[0]["current"])
        self.assertEqual(rows[1]["id"], "sess-2")
        self.assertEqual(rows[1]["browser"], "Firefox")
        self.assertEqual(rows[1]["os"], "Windows")
        self.assertFalse(rows[1]["current"])

    @override_settings(
        OPENID_CONNECT_AUTH_SERVERS={
            **OPENID_CONNECT_AUTH_SERVERS,
            "default": {
                **OPENID_CONNECT_AUTH_SERVERS["default"],
                "ACCOUNT_ENDPOINT": "https://idp.example.com/realms/r/account",
            },
        },
        OPENID_CONNECT_VIEWSET_CONFIG=OPENID_CONNECT_VIEWSET_CONFIG,
    )
    def test_sessions_list_marks_only_sid_match_current_when_grouped(self):
        """Two browsers on one machine (e.g. normal + incognito on
        localhost) collapse into a single device that Keycloak flags
        ``current``, with both nested sessions flagged ``current`` too.
        Only the session whose id matches the id_token ``sid`` should
        render as current — not both."""
        view = KeycloakOpenIDConnectViewset.as_view({"get": "sessions_list"})
        request = self.factory.get("/")
        request.session = {
            "oidc_access_token:default": "stashed.access.token",
            "oidc_id_token:default": "stashed.id.token",
        }

        upstream = MagicMock(status_code=200)
        upstream.content = b"[...]"
        upstream.json.return_value = [
            {
                "browser": "Chrome",
                "os": "Mac OS X",
                "current": True,
                "sessions": [
                    {"id": "sess-old", "current": True, "clients": []},
                    {"id": "sess-current", "current": True, "clients": []},
                ],
            },
        ]
        with (
            patch("oidc.keycloak._sid_from_id_token", return_value="sess-current"),
            patch("oidc.client.requests.request", return_value=upstream),
        ):
            response = view(request, auth_server="default")

        self.assertEqual(response.status_code, 200)
        by_id = {row["id"]: row for row in response.data}
        self.assertFalse(by_id["sess-old"]["current"])
        self.assertTrue(by_id["sess-current"]["current"])

    @override_settings(
        OPENID_CONNECT_AUTH_SERVERS={
            **OPENID_CONNECT_AUTH_SERVERS,
            "default": {
                **OPENID_CONNECT_AUTH_SERVERS["default"],
                "ACCOUNT_ENDPOINT": "https://idp.example.com/realms/r/account",
            },
        },
        OPENID_CONNECT_VIEWSET_CONFIG=OPENID_CONNECT_VIEWSET_CONFIG,
    )
    def test_sessions_revoke_one_forwards_id(self):
        view = KeycloakOpenIDConnectViewset.as_view({"delete": "sessions_revoke_one"})
        request = self.factory.delete("/")
        request.session = {
            "oidc_access_token:default": "stashed.access.token",
            "oidc_id_token:default": "header.payload.sig",
        }
        upstream = MagicMock(status_code=204, content=b"")
        with (
            patch("oidc.keycloak._sid_from_id_token", return_value="current-sid"),
            patch(
                "oidc.client.requests.request", return_value=upstream
            ) as mock_request,
        ):
            response = view(request, auth_server="default", session_id="other-sid")

        self.assertEqual(response.status_code, 204)
        args, _ = mock_request.call_args
        self.assertEqual(args[0], "DELETE")
        self.assertTrue(args[1].endswith("/sessions/other-sid"))

    @override_settings(
        OPENID_CONNECT_AUTH_SERVERS={
            **OPENID_CONNECT_AUTH_SERVERS,
            "default": {
                **OPENID_CONNECT_AUTH_SERVERS["default"],
                "ACCOUNT_ENDPOINT": "https://idp.example.com/realms/r/account",
            },
        },
        OPENID_CONNECT_VIEWSET_CONFIG=OPENID_CONNECT_VIEWSET_CONFIG,
    )
    def test_sessions_revoke_one_rejects_current_session(self):
        view = KeycloakOpenIDConnectViewset.as_view({"delete": "sessions_revoke_one"})
        request = self.factory.delete("/")
        request.session = {
            "oidc_access_token:default": "stashed.access.token",
            "oidc_id_token:default": "header.payload.sig",
        }
        with (
            patch("oidc.keycloak._sid_from_id_token", return_value="current-sid"),
            patch("oidc.client.requests.request") as mock_request,
        ):
            response = view(request, auth_server="default", session_id="current-sid")

        self.assertEqual(response.status_code, 409)
        # Crucial: we never reach Keycloak.
        mock_request.assert_not_called()

    @override_settings(
        OPENID_CONNECT_AUTH_SERVERS={
            **OPENID_CONNECT_AUTH_SERVERS,
            "default": {
                **OPENID_CONNECT_AUTH_SERVERS["default"],
                "ACCOUNT_ENDPOINT": "https://idp.example.com/realms/r/account",
            },
        },
        OPENID_CONNECT_VIEWSET_CONFIG=OPENID_CONNECT_VIEWSET_CONFIG,
    )
    def test_sessions_revoke_others_passes_current_false(self):
        """DELETE /sessions revokes every session EXCEPT the current one."""
        view = KeycloakOpenIDConnectViewset.as_view(
            {"delete": "sessions_revoke_others"}
        )
        request = self.factory.delete("/")
        request.session = {"oidc_access_token:default": "stashed.access.token"}

        upstream = MagicMock(status_code=204, content=b"")
        with patch(
            "oidc.client.requests.request", return_value=upstream
        ) as mock_request:
            response = view(request, auth_server="default")

        # 204 No Content is Keycloak's natural success code for DELETE;
        # passed through verbatim so the SPA can treat `res.ok` uniformly.
        self.assertEqual(response.status_code, 204)
        args, _ = mock_request.call_args
        self.assertEqual(args[0], "DELETE")
        self.assertIn("/sessions?current=false", args[1])

    @override_settings(
        OPENID_CONNECT_AUTH_SERVERS={
            **OPENID_CONNECT_AUTH_SERVERS,
            "default": {
                **OPENID_CONNECT_AUTH_SERVERS["default"],
                "ACCOUNT_ENDPOINT": "https://idp.example.com/realms/r/account",
            },
        },
        OPENID_CONNECT_VIEWSET_CONFIG=OPENID_CONNECT_VIEWSET_CONFIG,
    )
    def test_linked_list_forwards_keycloak_body_verbatim(self):
        view = KeycloakOpenIDConnectViewset.as_view({"get": "linked_list"})
        request = self.factory.get("/")
        request.session = {"oidc_access_token:default": "stashed.access.token"}

        upstream = MagicMock(status_code=200)
        upstream.content = b"[...]"
        keycloak_body = [
            {
                "providerAlias": "google",
                "providerName": "Google",
                "displayName": "Google",
                "connected": True,
                "social": True,
                "linkedUsername": "alice@gmail.com",
            }
        ]
        upstream.json.return_value = keycloak_body
        with patch("oidc.client.requests.request", return_value=upstream):
            response = view(request, auth_server="default")

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data, keycloak_body)

    @override_settings(
        OPENID_CONNECT_AUTH_SERVERS={
            **OPENID_CONNECT_AUTH_SERVERS,
            "default": {
                **OPENID_CONNECT_AUTH_SERVERS["default"],
                "ACCOUNT_ENDPOINT": "https://idp.example.com/realms/r/account",
            },
        },
        OPENID_CONNECT_VIEWSET_CONFIG=OPENID_CONNECT_VIEWSET_CONFIG,
    )
    def test_linked_unlink_forwards_provider_alias(self):
        view = KeycloakOpenIDConnectViewset.as_view({"delete": "linked_unlink"})
        request = self.factory.delete("/")
        request.session = {"oidc_access_token:default": "stashed.access.token"}
        upstream = MagicMock(status_code=204, content=b"")
        with patch(
            "oidc.client.requests.request", return_value=upstream
        ) as mock_request:
            response = view(request, auth_server="default", provider="google")
        self.assertEqual(response.status_code, 204)
        args, _ = mock_request.call_args
        self.assertTrue(args[1].endswith("/linked-accounts/google"))

    @override_settings(
        OPENID_CONNECT_AUTH_SERVERS={
            **OPENID_CONNECT_AUTH_SERVERS,
            "default": {
                **OPENID_CONNECT_AUTH_SERVERS["default"],
                "ACCOUNT_ENDPOINT": "https://idp.example.com/realms/r/account",
            },
        },
        OPENID_CONNECT_VIEWSET_CONFIG=OPENID_CONNECT_VIEWSET_CONFIG,
    )
    def test_linked_unlink_rejects_invalid_provider_alias(self):
        view = KeycloakOpenIDConnectViewset.as_view({"delete": "linked_unlink"})
        request = self.factory.delete("/")
        request.session = {"oidc_access_token:default": "stashed.access.token"}
        with patch("oidc.client.requests.request") as mock_request:
            response = view(request, auth_server="default", provider="../etc/passwd")
        self.assertEqual(response.status_code, 400)
        mock_request.assert_not_called()

    @override_settings(
        OPENID_CONNECT_AUTH_SERVERS={
            **OPENID_CONNECT_AUTH_SERVERS,
            "default": {
                **OPENID_CONNECT_AUTH_SERVERS["default"],
                "ACCOUNT_ENDPOINT": "https://idp.example.com/realms/r/account",
            },
        },
        OPENID_CONNECT_VIEWSET_CONFIG=OPENID_CONNECT_VIEWSET_CONFIG,
    )
    def test_linked_link_url_forwards_body(self):
        """The link-url action forwards Keycloak's linked-account
        representation verbatim — the SPA extracts ``accountLinkUri``
        client-side."""
        view = KeycloakOpenIDConnectViewset.as_view({"get": "linked_link_url"})
        request = self.factory.get("/")
        request.session = {"oidc_access_token:default": "stashed.access.token"}

        upstream = MagicMock(status_code=200)
        upstream.content = b"{...}"
        upstream.json.return_value = {
            "accountLinkUri": "https://idp.example.com/realms/r/broker/google/link?nonce=n&hash=h",
            "nonce": "n",
            "hash": "h",
        }
        with patch("oidc.client.requests.request", return_value=upstream):
            response = view(request, auth_server="default", provider="google")

        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            response.data,
            {
                "accountLinkUri": (
                    "https://idp.example.com/realms/r/broker/google/link"
                    "?nonce=n&hash=h"
                ),
                "nonce": "n",
                "hash": "h",
            },
        )

    @override_settings(
        OPENID_CONNECT_AUTH_SERVERS={
            **OPENID_CONNECT_AUTH_SERVERS,
            "default": {
                **OPENID_CONNECT_AUTH_SERVERS["default"],
                "ACCOUNT_ENDPOINT": "https://idp.example.com/realms/r/account",
            },
        },
        OPENID_CONNECT_VIEWSET_CONFIG=OPENID_CONNECT_VIEWSET_CONFIG,
    )
    def test_credentials_list_forwards_body(self):
        """The credentials action forwards Keycloak's nested
        credential-metadata wire shape verbatim — reshaping for
        rendering (flattening ``userCredentialMetadatas`` →
        ``credential``) happens client-side in the SPA."""
        view = KeycloakOpenIDConnectViewset.as_view({"get": "credentials_list"})
        request = self.factory.get("/")
        request.session = {"oidc_access_token:default": "stashed.access.token"}

        upstream_body = [
            {
                "type": "otp",
                "category": "two-factor",
                "displayName": "otp-display-name",
                "userCredentialMetadatas": [
                    {
                        "credential": {
                            "id": "cred-1",
                            "type": "otp",
                            "userLabel": "iPhone",
                            "createdDate": 1715000000000,
                        }
                    }
                ],
            },
            {
                "type": "password",
                "category": "basic-authentication",
                "displayName": "password-display-name",
                "userCredentialMetadatas": [
                    {"credential": {"id": "cred-pw", "type": "password"}}
                ],
            },
        ]
        upstream = MagicMock(status_code=200)
        upstream.content = b"[...]"
        upstream.json.return_value = upstream_body
        with patch("oidc.client.requests.request", return_value=upstream):
            response = view(request, auth_server="default")

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data, upstream_body)

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


class TestViewsetClassInjection(TestCase):
    """Which viewset ``oidc.urls`` routes to.

    Without injection a deployment that needs its own subclass has to copy the
    whole URLconf, then mirror every future route and view kwarg by hand.
    """

    def test_defaults_to_the_user_model_viewset(self):
        self.assertIs(get_viewset_class(), UserModelOpenIDConnectViewset)

    @override_settings(
        OPENID_CONNECT_VIEWSET_CONFIG={
            **OPENID_CONNECT_VIEWSET_CONFIG,
            "USE_RAPIDPRO_VIEWSET": True,
        }
    )
    def test_rapidpro_boolean_still_honoured(self):
        """Back-compat: the older boolean form keeps working."""
        self.assertIs(get_viewset_class(), RapidProOpenIDConnectViewset)

    @override_settings(
        OPENID_CONNECT_VIEWSET_CONFIG={
            **OPENID_CONNECT_VIEWSET_CONFIG,
            "VIEWSET_CLASS": "tests.project_viewsets.InjectedViewset",
        }
    )
    def test_dotted_path_routes_to_a_project_subclass(self):
        self.assertIs(get_viewset_class(), InjectedViewset)

    @override_settings(
        OPENID_CONNECT_VIEWSET_CONFIG={
            **OPENID_CONNECT_VIEWSET_CONFIG,
            "VIEWSET_CLASS": "tests.project_viewsets.InjectedViewset",
            "USE_RAPIDPRO_VIEWSET": True,
        }
    )
    def test_dotted_path_wins_over_the_boolean(self):
        """Pin the precedence: a deployment that names a class means it."""
        self.assertIs(get_viewset_class(), InjectedViewset)

    @override_settings(
        OPENID_CONNECT_VIEWSET_CONFIG={
            **OPENID_CONNECT_VIEWSET_CONFIG,
            "VIEWSET_CLASS": "tests.project_viewsets.NoSuchViewset",
        }
    )
    def test_unimportable_path_fails_loudly(self):
        """A typo must not silently fall back to the default viewset — that
        would drop a subclass's access rules with nothing to notice it."""
        with self.assertRaises(ImportError):
            get_viewset_class()


@override_settings(ROOT_URLCONF="tests.keycloak_urls")
class TestAccountRoutes(TestCase):
    """URL→action wiring smoke test; per-action behaviour is covered
    by the per-action tests above."""

    ROUTES = (
        ("/oidc/example/sessions", "get", "sessions_list", {}),
        ("/oidc/example/sessions", "delete", "sessions_revoke_others", {}),
        (
            "/oidc/example/sessions/abc-123",
            "delete",
            "sessions_revoke_one",
            {"session_id": "abc-123"},
        ),
        ("/oidc/example/linked-accounts", "get", "linked_list", {}),
        (
            "/oidc/example/linked-accounts/google",
            "delete",
            "linked_unlink",
            {"provider": "google"},
        ),
        (
            "/oidc/example/linked-accounts/google/link-url",
            "get",
            "linked_link_url",
            {"provider": "google"},
        ),
        ("/oidc/example/credentials", "get", "credentials_list", {}),
    )

    def test_routes_resolve_to_their_actions(self):
        for path, method, action, url_kwargs in self.ROUTES:
            with self.subTest(path=path, method=method):
                match = resolve(path)
                self.assertEqual(match.func.actions[method], action)
                for key, value in url_kwargs.items():
                    self.assertEqual(match.kwargs[key], value)

    def test_every_proxy_route_carries_the_csrf_permission(self):
        """Each action declares its own gate, so an action added without one
        would be routed and unguarded.

        Enumerated from the router rather than from ``ROUTES``: checking a
        hand-written list only proves the routes someone remembered to add to
        it, which is exactly the case that never fails.

        Both keys matter: empty ``authentication_classes`` is what takes these
        routes out of DRF's SessionAuthentication/CSRF path, and the permission
        is what replaces it. Either one alone is a hole.
        """
        proxy_actions = {
            a.__name__ for a in KeycloakOpenIDConnectViewset.get_extra_actions()
        } - {a.__name__ for a in UserModelOpenIDConnectViewset.get_extra_actions()}
        self.assertTrue(proxy_actions, "no proxy actions found — check the mixin")

        reached = set()
        for pattern in get_resolver().url_patterns:
            view = pattern.callback
            handled = set(getattr(view, "actions", {}).values())
            if not handled & proxy_actions:
                continue
            with self.subTest(pattern=str(pattern.pattern)):
                initkwargs = view.initkwargs
                self.assertIn(
                    IsCsrfSafeAccountRequest,
                    initkwargs.get("permission_classes", []),
                )
                self.assertEqual(initkwargs.get("authentication_classes"), [])
            reached |= handled & proxy_actions

        # Every proxy action is actually routed, so none slipped past the loop.
        self.assertEqual(reached, proxy_actions)


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
        self.assertEqual(response.url, "https://requested.example.com/dashboard")

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


class TestSessionAction(TestCase):
    """Tests for the challenge-free ``session`` probe action."""

    def setUp(self):
        super().setUp()
        self.factory = APIRequestFactory()
        cache.clear()
        self.user = User.objects.create(
            username="jdoe", email="jdoe@example.com", is_active=True
        )

    def _sso_token(self, value, claim="email", **claims):
        return jwt.encode({claim: value, **claims}, "abc", algorithm="HS256")

    def _get_session(self, sso=None):
        request = self.factory.get("/oidc/default/session")
        if sso is not None:
            request.COOKIES["SSO"] = sso
        view = BaseOpenIDConnectViewset.as_view({"get": "session"})
        return view(request, auth_server="default")

    @override_settings(OPENID_CONNECT_VIEWSET_CONFIG=OPENID_CONNECT_VIEWSET_CONFIG)
    def test_valid_sso_cookie_returns_username(self):
        response = self._get_session(self._sso_token("jdoe@example.com"))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data, {"username": "jdoe"})
        # No token material or PII leaks out of the base payload.
        self.assertNotIn("email", response.data)
        self.assertNotIn("api_token", response.data)
        self.assertNotIn("temp_token", response.data)
        self.assertEqual(response["Cache-Control"], "no-store")
        # Crucially: no native browser auth dialog can be triggered.
        self.assertFalse(response.has_header("WWW-Authenticate"))

    @override_settings(
        OPENID_CONNECT_VIEWSET_CONFIG={
            **OPENID_CONNECT_VIEWSET_CONFIG,
            "USE_SSO_COOKIE": False,
        }
    )
    def test_sso_cookie_disabled_returns_plain_401_even_with_valid_cookie(self):
        response = self._get_session(self._sso_token("jdoe@example.com"))
        self.assertEqual(response.status_code, 401)
        self.assertEqual(response["Cache-Control"], "no-store")
        self.assertFalse(response.has_header("WWW-Authenticate"))

    @override_settings(OPENID_CONNECT_VIEWSET_CONFIG=OPENID_CONNECT_VIEWSET_CONFIG)
    def test_missing_cookie_returns_plain_401(self):
        response = self._get_session()
        self.assertEqual(response.status_code, 401)
        self.assertIn("detail", response.data)
        self.assertEqual(response["Cache-Control"], "no-store")
        self.assertFalse(response.has_header("WWW-Authenticate"))

    @override_settings(OPENID_CONNECT_VIEWSET_CONFIG=OPENID_CONNECT_VIEWSET_CONFIG)
    def test_url_route_uses_json_renderer_for_browser_accept_header(self):
        response = self.client.get(
            "/oidc/default/session",
            HTTP_ACCEPT=(
                "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
            ),
        )
        self.assertEqual(response.status_code, 401)
        self.assertEqual(response["Content-Type"], "application/json")
        self.assertFalse(response.has_header("WWW-Authenticate"))

    @override_settings(OPENID_CONNECT_VIEWSET_CONFIG=OPENID_CONNECT_VIEWSET_CONFIG)
    def test_authorization_header_does_not_trigger_browser_auth_challenge(self):
        request = self.factory.get(
            "/oidc/default/session", HTTP_AUTHORIZATION="Basic invalid"
        )
        response = BaseOpenIDConnectViewset.as_view({"get": "session"})(
            request, auth_server="default"
        )
        self.assertEqual(response.status_code, 401)
        self.assertFalse(response.has_header("WWW-Authenticate"))

    @override_settings(OPENID_CONNECT_VIEWSET_CONFIG=OPENID_CONNECT_VIEWSET_CONFIG)
    def test_invalid_jwt_returns_plain_401(self):
        response = self._get_session("not-a-jwt")
        self.assertEqual(response.status_code, 401)
        self.assertFalse(response.has_header("WWW-Authenticate"))

    @override_settings(
        OPENID_CONNECT_VIEWSET_CONFIG={
            **OPENID_CONNECT_VIEWSET_CONFIG,
            "SSO_COOKIE_DATA": "username",
        }
    )
    def test_configured_sso_cookie_data_uses_matching_claim_and_user_field(self):
        response = self._get_session(self._sso_token("jdoe", claim="username"))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data, {"username": "jdoe"})

    @override_settings(
        OPENID_CONNECT_VIEWSET_CONFIG={
            **OPENID_CONNECT_VIEWSET_CONFIG,
            "SSO_COOKIE_DATA": "username",
        }
    )
    def test_configured_sso_cookie_data_accepts_legacy_email_claim(self):
        response = self._get_session(self._sso_token("jdoe"))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data, {"username": "jdoe"})

    @override_settings(OPENID_CONNECT_VIEWSET_CONFIG=OPENID_CONNECT_VIEWSET_CONFIG)
    def test_expired_jwt_returns_plain_401(self):
        response = self._get_session(self._sso_token("jdoe@example.com", exp=0))
        self.assertEqual(response.status_code, 401)
        self.assertFalse(response.has_header("WWW-Authenticate"))

    @override_settings(OPENID_CONNECT_VIEWSET_CONFIG=OPENID_CONNECT_VIEWSET_CONFIG)
    def test_unknown_user_returns_plain_401(self):
        response = self._get_session(self._sso_token("nobody@example.com"))
        self.assertEqual(response.status_code, 401)
        self.assertFalse(response.has_header("WWW-Authenticate"))

    @override_settings(
        OPENID_CONNECT_VIEWSET_CONFIG={
            **OPENID_CONNECT_VIEWSET_CONFIG,
            "REDIRECT_AFTER_AUTH": "http://localhost:3000",
            "SSO_COOKIE_DATA": "username",
        }
    )
    def test_generated_sso_cookie_uses_configured_claim(self):
        request = self.factory.get("/")
        response = BaseOpenIDConnectViewset().generate_successful_response(
            request, self.user
        )
        sso = response.cookies.get("SSO").value
        payload = jwt.decode(sso, "abc", algorithms=["HS256"])
        self.assertEqual(payload, {"username": "jdoe"})

        session_response = self._get_session(sso)
        self.assertEqual(session_response.status_code, 200)
        self.assertEqual(session_response.data, {"username": "jdoe"})

    @override_settings(OPENID_CONNECT_VIEWSET_CONFIG=OPENID_CONNECT_VIEWSET_CONFIG)
    def test_is_session_allowed_hook_can_reject(self):
        class Restricted(BaseOpenIDConnectViewset):
            def is_session_allowed(self, user):
                return False

        request = self.factory.get("/oidc/default/session")
        request.COOKIES["SSO"] = self._sso_token("jdoe@example.com")
        response = Restricted.as_view({"get": "session"})(
            request, auth_server="default"
        )
        self.assertEqual(response.status_code, 401)
        self.assertFalse(response.has_header("WWW-Authenticate"))


@override_settings(ROOT_URLCONF="tests.keycloak_urls")
class AccountProxyCsrfTests(TestCase):
    """CSRF gate on the state-changing account-proxy actions: unsafe methods
    require a custom header AND a trusted Origin."""

    def setUp(self):
        self.factory = APIRequestFactory()
        self.perm = IsCsrfSafeAccountRequest()
        self.view = SimpleNamespace(kwargs={"auth_server": "default"})
        self.header_kwarg = {
            "HTTP_" + get_account_request_header().upper().replace("-", "_"): "1"
        }

    @override_settings(
        OPENID_CONNECT_VIEWSET_CONFIG={
            **OPENID_CONNECT_VIEWSET_CONFIG,
            "ACCOUNT_REQUEST_HEADER": "X-Acme-Account-Request",
        }
    )
    def test_configured_header_replaces_the_default(self):
        """A deployment that renames the header is gated on its own name, and
        the shipped default stops working — otherwise the setting would only
        widen what is accepted rather than move it."""
        configured = self.factory.post("/", HTTP_X_ACME_ACCOUNT_REQUEST="1")
        self.assertTrue(self.perm.has_permission(configured, self.view))

        shipped_default = self.factory.post("/", HTTP_X_ONA_ACCOUNT_REQUEST="1")
        self.assertFalse(self.perm.has_permission(shipped_default, self.view))

    @override_settings(
        OPENID_CONNECT_VIEWSET_CONFIG={
            **OPENID_CONNECT_VIEWSET_CONFIG,
            "ACCOUNT_REQUEST_HEADER": "X-Acme-Account-Request",
        }
    )
    def test_denial_message_names_the_configured_header(self):
        """Pin: the message is resolved per request. As a class-level f-string
        it would freeze the default at import and tell operators to send a
        header the deployment no longer accepts."""
        self.assertIn("X-Acme-Account-Request", self.perm.message)
        self.assertNotIn("X-Ona-Account-Request", self.perm.message)

    def test_defaults_to_the_shipped_header_when_unconfigured(self):
        self.assertEqual(get_account_request_header(), "X-Ona-Account-Request")

    def test_safe_method_needs_no_header(self):
        """GET/HEAD/OPTIONS need no header — the Origin allowlist still
        applies to them; see TestReadsAreOriginGated."""
        self.assertTrue(self.perm.has_permission(self.factory.get("/"), self.view))

    def test_unsafe_without_header_denied(self):
        """POST/DELETE without the header are refused by the permission."""
        self.assertFalse(self.perm.has_permission(self.factory.post("/"), self.view))
        self.assertFalse(self.perm.has_permission(self.factory.delete("/"), self.view))

    def test_unsafe_with_header_no_origin_allowed(self):
        """Header + no Origin (same-origin requests may omit it) → allowed."""
        request = self.factory.post("/", **self.header_kwarg)
        self.assertTrue(self.perm.has_permission(request, self.view))

    def test_unsafe_same_origin_allowed(self):
        """Header + the request's own origin → allowed."""
        request = self.factory.post(
            "/", HTTP_ORIGIN="http://testserver", **self.header_kwarg
        )
        self.assertTrue(self.perm.has_permission(request, self.view))

    def test_unsafe_untrusted_origin_denied(self):
        """Header present but a foreign Origin → refused. This is the layer
        that holds even if the deployment's CORS is permissive."""
        request = self.factory.post(
            "/", HTTP_ORIGIN="https://evil.example", **self.header_kwarg
        )
        self.assertFalse(self.perm.has_permission(request, self.view))

    def test_unsafe_null_origin_denied(self):
        """Origin: null (sandboxed iframe / opaque origin) is host-less and
        must not be treated as same-origin-safe."""
        request = self.factory.post("/", HTTP_ORIGIN="null", **self.header_kwarg)
        self.assertFalse(self.perm.has_permission(request, self.view))

    @override_settings(
        OPENID_CONNECT_AUTH_SERVERS={
            **OPENID_CONNECT_AUTH_SERVERS,
            "default": {
                **OPENID_CONNECT_AUTH_SERVERS["default"],
                "LOGIN_REDIRECT_ALLOWED_HOSTS": ["app.example.com"],
            },
        }
    )
    def test_unsafe_allowlisted_cross_origin_allowed(self):
        """A configured SPA origin (via LOGIN_REDIRECT_ALLOWED_HOSTS) → ok."""
        request = self.factory.post(
            "/", HTTP_ORIGIN="https://app.example.com", **self.header_kwarg
        )
        self.assertTrue(self.perm.has_permission(request, self.view))

    @override_settings(
        OPENID_CONNECT_AUTH_SERVERS={
            **OPENID_CONNECT_AUTH_SERVERS,
            "default": {
                **OPENID_CONNECT_AUTH_SERVERS["default"],
                "ACCOUNT_ENDPOINT": "https://idp.example.com/realms/r/account",
            },
        },
        OPENID_CONNECT_VIEWSET_CONFIG=OPENID_CONNECT_VIEWSET_CONFIG,
    )
    def test_permitted_request_reaches_the_action(self):
        """Header + no cross-origin Origin: the permission passes and the
        action runs through to a concrete success."""
        view = KeycloakOpenIDConnectViewset.as_view(
            {"delete": "sessions_revoke_others"},
            authentication_classes=[],
            permission_classes=[IsCsrfSafeAccountRequest],
        )
        request = self.factory.delete("/", **self.header_kwarg)
        request.session = {"oidc_access_token:default": "t"}
        mock_response = MagicMock()
        mock_response.status_code = 204
        mock_response.content = b""
        with patch("oidc.client.requests.request", return_value=mock_response):
            response = view(request, auth_server="default")
        self.assertEqual(response.status_code, 204)


class TestKeycloakProxyIsOptIn(TestCase):
    """The account proxy is Keycloak's, so the provider-neutral viewset must
    not carry it and a deployment that doesn't opt in gets no routes for it."""

    ACCOUNT_ACTIONS = frozenset(
        {
            "credentials_list",
            "linked_link_url",
            "linked_list",
            "linked_unlink",
            "sessions_list",
            "sessions_revoke_one",
        }
    )

    def test_default_viewset_carries_no_account_actions(self):
        actions = {
            a.__name__ for a in UserModelOpenIDConnectViewset.get_extra_actions()
        }
        self.assertEqual(actions & self.ACCOUNT_ACTIONS, set())

    def test_mixing_the_mixin_in_adds_them(self):
        actions = {a.__name__ for a in KeycloakOpenIDConnectViewset.get_extra_actions()}
        self.assertTrue(self.ACCOUNT_ACTIONS.issubset(actions))

    def test_default_urlconf_has_no_account_routes(self):
        """Not a 503 — the paths simply do not resolve."""
        for path in (
            "/oidc/example/sessions",
            "/oidc/example/linked-accounts",
            "/oidc/example/credentials",
        ):
            with self.subTest(path=path):
                with self.assertRaises(Resolver404):
                    resolve(path)


@override_settings(OPENID_CONNECT_VIEWSET_CONFIG=OPENID_CONNECT_VIEWSET_CONFIG)
class TestTokenStashIsOptIn(TestCase):
    """``callback`` only keeps the access/refresh pair for a viewset that
    says it needs them -- a stashed refresh token is credential material at
    rest, so a deployment that never calls the IdP on the user's behalf
    should not accumulate one."""

    TOKENS = {
        "id_token": "idp-id-token",
        "access_token": "idp-access-token",
        "refresh_token": "idp-refresh-token",
    }

    def setUp(self):
        self.factory = APIRequestFactory()

    def _run_callback(self, viewset_class):
        """Drive a full auth-code callback and return the resulting session."""
        view = viewset_class.as_view({"post": "callback"})
        with (
            patch(
                "oidc.viewsets.OpenIDClient.retrieve_tokens_using_auth_code",
                return_value=dict(self.TOKENS),
            ),
            patch(
                "oidc.viewsets.OpenIDClient.verify_and_decode_id_token",
                return_value={
                    "name": "Stash User",
                    "preferred_username": "stash@example.com",
                    "given_name": "Stash",
                    "family_name": "User",
                    "email": "stash@example.com",
                },
            ),
        ):
            request = self.factory.post("/", data={"code": "auth-code"})
            request.session = {}
            response = view(request, auth_server="default")
        self.assertEqual(response.status_code, 302)
        return request.session

    def test_default_viewset_does_not_stash(self):
        session = self._run_callback(UserModelOpenIDConnectViewset)
        self.assertNotIn("oidc_access_token:default", session)
        self.assertNotIn("oidc_refresh_token:default", session)
        # The id_token is still kept -- logout replays it as id_token_hint.
        self.assertEqual(session.get("oidc_id_token:default"), "idp-id-token")

    def test_the_account_proxy_opts_in(self):
        session = self._run_callback(KeycloakOpenIDConnectViewset)
        self.assertEqual(session["oidc_access_token:default"], "idp-access-token")
        self.assertEqual(session["oidc_refresh_token:default"], "idp-refresh-token")


class TestForgedHostHeader(TestCase):
    """A Host header ALLOWED_HOSTS rejects must not crash the origin check.

    ``_trusted_spa_hosts`` adds ``request.get_host()`` as a convenience for
    same-origin deployments, and that call raises ``DisallowedHost``. The
    configured allowlist is the static trust root, so it has to stand alone.
    """

    def setUp(self):
        self.factory = APIRequestFactory()
        self.perm = IsCsrfSafeAccountRequest()
        self.view = SimpleNamespace(kwargs={"auth_server": "default"})
        self.header_kwarg = {
            "HTTP_" + get_account_request_header().upper().replace("-", "_"): "1"
        }

    @override_settings(
        ALLOWED_HOSTS=["real.example.com"],
        OPENID_CONNECT_AUTH_SERVERS={
            **OPENID_CONNECT_AUTH_SERVERS,
            "default": {
                **OPENID_CONNECT_AUTH_SERVERS["default"],
                "LOGIN_REDIRECT_ALLOWED_HOSTS": ["spa.example.com"],
            },
        },
    )
    def test_forged_host_falls_back_to_the_configured_allowlist(self):
        """Denied on its merits (403), not by an escaping DisallowedHost."""
        forged = self.factory.post(
            "/",
            HTTP_HOST="attacker.example.com",
            HTTP_ORIGIN="https://evil.example.com",
            **self.header_kwarg,
        )
        self.assertFalse(self.perm.has_permission(forged, self.view))

        # ...and a genuinely configured origin still passes, so the fallback
        # narrows the trust set rather than emptying it.
        configured = self.factory.post(
            "/",
            HTTP_HOST="attacker.example.com",
            HTTP_ORIGIN="https://spa.example.com",
            **self.header_kwarg,
        )
        self.assertTrue(self.perm.has_permission(configured, self.view))


class TestSessionIdPathTraversal(TestCase):
    """``session_id`` is interpolated into the upstream URL, and ``requests``
    resolves dot segments before sending — so ``..`` would escape
    ``/sessions/`` and issue the DELETE against the Keycloak account root.
    The route pattern allows dots, so the action has to reject them.
    """

    def setUp(self):
        self.factory = APIRequestFactory()

    @override_settings(
        OPENID_CONNECT_AUTH_SERVERS={
            **OPENID_CONNECT_AUTH_SERVERS,
            "default": {
                **OPENID_CONNECT_AUTH_SERVERS["default"],
                "ACCOUNT_ENDPOINT": "https://idp.example.com/realms/r/account",
            },
        },
        OPENID_CONNECT_VIEWSET_CONFIG=OPENID_CONNECT_VIEWSET_CONFIG,
    )
    def test_dot_segment_session_id_is_rejected_before_any_upstream_call(self):
        view = KeycloakOpenIDConnectViewset.as_view({"delete": "sessions_revoke_one"})
        for session_id in ("..", ".", "..%2f.."):
            with self.subTest(session_id=session_id):
                request = self.factory.delete("/")
                request.session = {"oidc_access_token:default": "t"}
                with patch("oidc.client.requests.request") as mock_request:
                    response = view(
                        request, auth_server="default", session_id=session_id
                    )
                self.assertEqual(response.status_code, 400)
                # The point of the guard: Keycloak is never contacted.
                mock_request.assert_not_called()

    @override_settings(
        OPENID_CONNECT_AUTH_SERVERS={
            **OPENID_CONNECT_AUTH_SERVERS,
            "default": {
                **OPENID_CONNECT_AUTH_SERVERS["default"],
                "ACCOUNT_ENDPOINT": "https://idp.example.com/realms/r/account",
            },
        },
        OPENID_CONNECT_VIEWSET_CONFIG=OPENID_CONNECT_VIEWSET_CONFIG,
    )
    def test_a_real_session_id_still_reaches_the_expected_url(self):
        """The guard must not narrow the endpoint to uselessness."""
        view = KeycloakOpenIDConnectViewset.as_view({"delete": "sessions_revoke_one"})
        request = self.factory.delete("/")
        request.session = {"oidc_access_token:default": "t"}
        mock_response = MagicMock(status_code=204, content=b"")
        with patch(
            "oidc.client.requests.request", return_value=mock_response
        ) as mock_request:
            response = view(
                request,
                auth_server="default",
                session_id="6b1f2c3d-4e5a-6789-0abc-def012345678",
            )
        self.assertEqual(response.status_code, 204)
        args, _kwargs = mock_request.call_args
        self.assertEqual(
            args[1],
            "https://idp.example.com/realms/r/account/sessions/"
            "6b1f2c3d-4e5a-6789-0abc-def012345678",
        )


class TestMisconfigurationIsNotAnOutage(TestCase):
    """An endpoint we never configured is our gap, not the IdP being down.

    Both ``ACCOUNT_ENDPOINT`` and ``TOKEN_ENDPOINT`` are guarded the same way
    and surface as 503, so nobody is sent to check on a healthy Keycloak.
    """

    def setUp(self):
        self.factory = APIRequestFactory()

    @override_settings(
        OPENID_CONNECT_AUTH_SERVERS={
            **OPENID_CONNECT_AUTH_SERVERS,
            "default": {
                **OPENID_CONNECT_AUTH_SERVERS["default"],
                "ACCOUNT_ENDPOINT": "https://idp.example.com/realms/r/account",
                "TOKEN_ENDPOINT": "",
            },
        },
        OPENID_CONNECT_VIEWSET_CONFIG=OPENID_CONNECT_VIEWSET_CONFIG,
    )
    def test_unset_token_endpoint_is_503_not_502(self):
        """Reached only on the refresh path, so drive a 401 to get there."""
        view = KeycloakOpenIDConnectViewset.as_view({"get": "linked_list"})
        request = self.factory.get("/")
        request.session = {
            "oidc_access_token:default": "expired.access.token",
            "oidc_refresh_token:default": "stashed.refresh.token",
        }

        unauthorized = MagicMock(status_code=401, content=b"{}")
        unauthorized.json.return_value = {"error": "invalid_token"}

        with (
            patch("oidc.client.requests.request", return_value=unauthorized),
            patch("oidc.client.requests.post") as mock_post,
        ):
            response = view(request, auth_server="default")

        self.assertEqual(response.status_code, 503)
        # The guard fires before the request is built, so no bogus URL is
        # handed to requests and no call leaves the process.
        mock_post.assert_not_called()

    @override_settings(
        OPENID_CONNECT_AUTH_SERVERS={
            **OPENID_CONNECT_AUTH_SERVERS,
            "default": {
                **OPENID_CONNECT_AUTH_SERVERS["default"],
                "ACCOUNT_ENDPOINT": "https://idp.example.com/realms/r/account",
            },
        },
        OPENID_CONNECT_VIEWSET_CONFIG=OPENID_CONNECT_VIEWSET_CONFIG,
    )
    def test_a_non_json_token_response_is_502_not_503(self):
        """``requests`` raises ``JSONDecodeError`` for a non-JSON body, and it
        subclasses both ``ValueError`` and ``RequestException``. Catching bare
        ``ValueError`` for the config case would swallow it and blame our own
        settings for what is a proxy or WAF returning an HTML interstitial."""
        view = KeycloakOpenIDConnectViewset.as_view({"get": "linked_list"})
        request = self.factory.get("/")
        request.session = {
            "oidc_access_token:default": "expired.access.token",
            "oidc_refresh_token:default": "stashed.refresh.token",
        }

        unauthorized = MagicMock(status_code=401, content=b"{}")
        unauthorized.json.return_value = {"error": "invalid_token"}
        html_body = MagicMock(status_code=200)
        html_body.raise_for_status = MagicMock()
        html_body.json.side_effect = requests.exceptions.JSONDecodeError(
            "Expecting value", "<html>", 0
        )

        with (
            patch("oidc.client.requests.request", return_value=unauthorized),
            patch("oidc.client.requests.post", return_value=html_body),
        ):
            response = view(request, auth_server="default")

        self.assertEqual(response.status_code, 502)

    def test_refresh_names_the_setting_it_is_missing(self):
        """The message has to say which setting, or the 503 is a scavenger
        hunt across every configured auth server."""
        client = OpenIDClient("default")
        client.token_endpoint = ""
        with self.assertRaises(ValueError) as ctx:
            client.refresh_access_token("some.refresh.token")
        self.assertIn("TOKEN_ENDPOINT", str(ctx.exception))
        self.assertIn("default", str(ctx.exception))


@override_settings(ROOT_URLCONF="tests.keycloak_urls")
class TestProxyErrorsAreAlwaysJson(TestCase):
    """These actions declare ``renderer_classes=[JSONRenderer]``, and the SPA
    reads the message out of ``body.error``. An error that answers in HTML
    degrades to a bare status code on the client, so every failure mode has
    to stay JSON."""

    @override_settings(
        OPENID_CONNECT_AUTH_SERVERS={
            **OPENID_CONNECT_AUTH_SERVERS,
            "default": {
                **OPENID_CONNECT_AUTH_SERVERS["default"],
                "ACCOUNT_ENDPOINT": "https://idp.example.com/realms/r/account",
            },
        },
        OPENID_CONNECT_VIEWSET_CONFIG=OPENID_CONNECT_VIEWSET_CONFIG,
    )
    def test_unknown_auth_server_answers_json(self):
        response = self.client.get("/oidc/nosuchserver/sessions")
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.headers["Content-Type"], "application/json")
        self.assertIn("error", response.json())


#: A second configured provider. The route picks the provider, so anything
#: the session stores globally is reachable from every provider's URL.
_TWO_PROVIDERS = {
    "default": {
        **OPENID_CONNECT_AUTH_SERVERS["default"],
        "ACCOUNT_ENDPOINT": "https://idp-a.example.com/realms/a/account",
    },
    "other": {
        **OPENID_CONNECT_AUTH_SERVERS["default"],
        "ACCOUNT_ENDPOINT": "https://idp-b.example.com/realms/b/account",
        "TOKEN_ENDPOINT": "https://idp-b.example.com/realms/b/token",
        "END_SESSION_ENDPOINT": "https://idp-b.example.com/realms/b/logout",
    },
}


@override_settings(
    OPENID_CONNECT_AUTH_SERVERS=_TWO_PROVIDERS,
    OPENID_CONNECT_VIEWSET_CONFIG=OPENID_CONNECT_VIEWSET_CONFIG,
)
class TestTokensAreScopedToAuthServer(TestCase):
    """Tokens belong to the provider that issued them.

    ``OPENID_CONNECT_AUTH_SERVERS`` is a keyed dict and every key gets its
    own route, so a session that stores tokens under one global key lets a
    request to provider B replay provider A's credentials against B's
    endpoints. Nothing here is about a hostile ``auth_server`` value --
    ``_get_client`` already 400s on unknown names -- it is about one
    configured provider receiving another's tokens.
    """

    def setUp(self):
        self.factory = APIRequestFactory()

    def _session_for(self, auth_server):
        """A session as ``callback`` leaves it after login to ``auth_server``."""
        view = KeycloakOpenIDConnectViewset.as_view({"post": "callback"})
        with (
            patch(
                "oidc.viewsets.OpenIDClient.retrieve_tokens_using_auth_code",
                return_value={
                    "id_token": f"{auth_server}-id-token",
                    "access_token": f"{auth_server}-access-token",
                    "refresh_token": f"{auth_server}-refresh-token",
                },
            ),
            patch(
                "oidc.viewsets.OpenIDClient.verify_and_decode_id_token",
                return_value={
                    "name": "Scoped User",
                    "preferred_username": "scoped@example.com",
                    "given_name": "Scoped",
                    "family_name": "User",
                    "email": "scoped@example.com",
                },
            ),
        ):
            request = self.factory.post("/", data={"code": "auth-code"})
            request.session = {}
            response = view(request, auth_server=auth_server)
        self.assertEqual(response.status_code, 302)
        return request.session

    def test_callback_does_not_stash_tokens_under_a_global_key(self):
        """The stash has to name its provider, or every other provider's
        route can read it."""
        session = self._session_for("default")

        self.assertNotIn("oidc_access_token", session)
        self.assertNotIn("oidc_refresh_token", session)
        self.assertNotIn("oidc_id_token", session)
        # ...but the tokens are still there, under a provider-scoped name.
        self.assertIn("default-access-token", session.values())
        self.assertIn("default-refresh-token", session.values())

    def test_another_providers_route_cannot_spend_this_providers_access_token(self):
        """The access-token leak: B's account endpoint must never receive a
        token A issued."""
        session = self._session_for("default")
        view = KeycloakOpenIDConnectViewset.as_view({"get": "linked_list"})
        request = self.factory.get("/")
        request.session = session

        # A well-formed response the call must never reach: a bare MagicMock
        # would blow up inside DRF on a regression instead of failing here.
        unreached = MagicMock(status_code=200, content=b"[]")
        unreached.json.return_value = []

        with patch(
            "oidc.client.requests.request", return_value=unreached
        ) as mock_request:
            response = view(request, auth_server="other")

        self.assertEqual(response.status_code, 401)
        mock_request.assert_not_called()

    def test_another_providers_route_cannot_replay_the_refresh_token(self):
        """The amplification, and the worse half of the bug.

        A foreign access token draws a 401 from B, and the retry path treats
        any 401 as "expired -- refresh it". Unscoped, that POSTs A's
        *long-lived* refresh token to B's token endpoint, so the failure
        mode leaks more than the request did.
        """
        session = self._session_for("default")
        view = KeycloakOpenIDConnectViewset.as_view({"get": "linked_list"})
        request = self.factory.get("/")
        request.session = session

        rejected = MagicMock(status_code=401, content=b"{}")
        rejected.json.return_value = {"error": "invalid_token"}

        with (
            patch("oidc.client.requests.request", return_value=rejected),
            patch("oidc.client.requests.post") as mock_post,
        ):
            response = view(request, auth_server="other")

        self.assertEqual(response.status_code, 401)
        mock_post.assert_not_called()

    def test_logout_does_not_replay_another_providers_id_token(self):
        """id_tokens carry sub/email/name, so handing A's to B's end-session
        endpoint as ``id_token_hint`` discloses the user to the wrong IdP."""
        session = self._session_for("default")
        view = KeycloakOpenIDConnectViewset.as_view({"get": "logout"})
        request = self.factory.get("/")
        request.session = session

        response = view(request, auth_server="other")

        self.assertEqual(response.status_code, 302)
        self.assertNotIn("id_token_hint", response.url)
        self.assertNotIn("default-id-token", response.url)

    def test_the_owning_provider_still_works(self):
        """The guard must not break the ordinary single-provider path."""
        session = self._session_for("default")
        view = KeycloakOpenIDConnectViewset.as_view({"get": "linked_list"})
        request = self.factory.get("/")
        request.session = session

        ok = MagicMock(status_code=200, content=b"[]")
        ok.json.return_value = []

        with patch("oidc.client.requests.request", return_value=ok) as mock_request:
            response = view(request, auth_server="default")

        self.assertEqual(response.status_code, 200)
        sent_headers = mock_request.call_args.kwargs["headers"]
        self.assertEqual(sent_headers["Authorization"], "Bearer default-access-token")


@override_settings(
    OPENID_CONNECT_AUTH_SERVERS=_TWO_PROVIDERS,
    OPENID_CONNECT_VIEWSET_CONFIG=OPENID_CONNECT_VIEWSET_CONFIG,
)
class TestLogoutClearsStashedTokens(TestCase):
    """Logging out has to drop the whole token stash, not just the hint.

    The end-session response is a *redirect*: the user may never complete
    it (closed tab, declined confirm screen, unreachable IdP), so the pop
    is the only point in the flow we control. Leaving the pair behind
    keeps a logged-out session spending credentials at the account proxy,
    and leaves a refresh token at rest in the session store -- the same
    thing ``stash_oidc_tokens`` exists to avoid for viewsets that never
    need one.
    """

    def setUp(self):
        self.factory = APIRequestFactory()

    def _logged_in_session(self, auth_server="default"):
        return {
            token_session_key(ID_TOKEN_SESSION_KEY, auth_server): "ey.id.token",
            token_session_key(ACCESS_TOKEN_SESSION_KEY, auth_server): "stashed.access",
            token_session_key(
                REFRESH_TOKEN_SESSION_KEY, auth_server
            ): "stashed.refresh",
        }

    def test_logout_drops_the_access_and_refresh_tokens(self):
        view = KeycloakOpenIDConnectViewset.as_view({"get": "logout"})
        request = self.factory.get("/")
        request.session = self._logged_in_session()

        response = view(request, auth_server="default")

        self.assertEqual(response.status_code, 302)
        self.assertNotIn("oidc_access_token:default", request.session)
        self.assertNotIn("oidc_refresh_token:default", request.session)
        self.assertNotIn("oidc_id_token:default", request.session)

    def test_logout_does_not_flush_unrelated_session_data(self):
        """Targeted removal, not a flush -- the session may be carrying
        state that has nothing to do with this provider."""
        view = KeycloakOpenIDConnectViewset.as_view({"get": "logout"})
        request = self.factory.get("/")
        request.session = {**self._logged_in_session(), "unrelated": "keep"}

        view(request, auth_server="default")

        self.assertEqual(request.session.get("unrelated"), "keep")

    def test_logout_leaves_another_providers_tokens_alone(self):
        """Logout is per-provider; ending the session at A must not sign
        the user out of B."""
        view = KeycloakOpenIDConnectViewset.as_view({"get": "logout"})
        request = self.factory.get("/")
        request.session = {
            **self._logged_in_session("default"),
            **self._logged_in_session("other"),
        }

        view(request, auth_server="default")

        self.assertEqual(
            request.session.get("oidc_access_token:other"), "stashed.access"
        )
        self.assertEqual(
            request.session.get("oidc_refresh_token:other"), "stashed.refresh"
        )

    def test_the_account_proxy_stops_working_after_logout(self):
        """The point of the whole thing: a logged-out session must not be
        able to keep calling Keycloak as the user."""
        logout_view = KeycloakOpenIDConnectViewset.as_view({"get": "logout"})
        request = self.factory.get("/")
        request.session = self._logged_in_session()
        logout_view(request, auth_server="default")

        proxy_view = KeycloakOpenIDConnectViewset.as_view({"get": "linked_list"})
        proxy_request = self.factory.get("/")
        proxy_request.session = request.session

        # See the note in TestTokensAreScopedToAuthServer: a well-formed
        # response keeps a regression failing on assert_not_called rather
        # than as a TypeError deep in DRF.
        unreached = MagicMock(status_code=200, content=b"[]")
        unreached.json.return_value = []

        with patch(
            "oidc.client.requests.request", return_value=unreached
        ) as mock_request:
            response = proxy_view(proxy_request, auth_server="default")

        self.assertEqual(response.status_code, 401)
        mock_request.assert_not_called()


@override_settings(
    OPENID_CONNECT_AUTH_SERVERS={
        **OPENID_CONNECT_AUTH_SERVERS,
        "default": {
            **OPENID_CONNECT_AUTH_SERVERS["default"],
            "ACCOUNT_ENDPOINT": "https://idp.example.com/realms/r/account",
        },
    },
    OPENID_CONNECT_VIEWSET_CONFIG=OPENID_CONNECT_VIEWSET_CONFIG,
)
class TestProviderAliasCharset(TestCase):
    """Keycloak accepts dots and mixed case in an identity-provider alias.

    Hostname-shaped aliases (``idp.acme.com``) are ordinary in the wild --
    Keycloak builds ``brokerUserId`` as ``alias + "." + federatedUserId``,
    which is what keycloak/keycloak#42209 is about -- so an allowlist
    without ``.`` silently 400s a correctly configured realm's IdP.

    The dot still cannot be allowed unconditionally: these values are
    interpolated into the upstream URL and ``requests`` resolves dot
    segments before sending, so an alias of exactly ``.`` or ``..`` would
    walk out of ``/linked-accounts/``. Since ``/`` is outside the charset
    there are no interior segments to consider, so rejecting those two
    exact values is the whole of it.
    """

    def setUp(self):
        self.factory = APIRequestFactory()

    def _unlink(self, provider):
        view = KeycloakOpenIDConnectViewset.as_view({"delete": "linked_unlink"})
        request = self.factory.delete("/")
        request.session = {"oidc_access_token:default": "stashed.access.token"}
        upstream = MagicMock(status_code=204, content=b"")
        with patch(
            "oidc.client.requests.request", return_value=upstream
        ) as mock_request:
            response = view(request, auth_server="default", provider=provider)
        return response, mock_request

    def _link_url(self, provider):
        view = KeycloakOpenIDConnectViewset.as_view({"get": "linked_link_url"})
        request = self.factory.get("/")
        request.session = {"oidc_access_token:default": "stashed.access.token"}
        upstream = MagicMock(status_code=200, content=b"{}")
        upstream.json.return_value = {}
        with patch(
            "oidc.client.requests.request", return_value=upstream
        ) as mock_request:
            response = view(request, auth_server="default", provider=provider)
        return response, mock_request

    def test_hostname_shaped_alias_is_accepted(self):
        response, mock_request = self._unlink("idp.acme.com")

        self.assertEqual(response.status_code, 204)
        args, _ = mock_request.call_args
        self.assertTrue(args[1].endswith("/linked-accounts/idp.acme.com"))

    def test_mixed_case_alias_is_accepted(self):
        """The session-id charset already allows uppercase; the alias one
        did not, so ``MyIdP`` was rejected for the same wrong reason."""
        response, mock_request = self._unlink("MyIdP")

        self.assertEqual(response.status_code, 204)
        args, _ = mock_request.call_args
        self.assertTrue(args[1].endswith("/linked-accounts/MyIdP"))

    def test_link_url_accepts_the_same_charset(self):
        """Both alias-taking actions validate identically -- one widened
        without the other is a confusing half-fix."""
        response, mock_request = self._link_url("idp.acme.com")

        self.assertEqual(response.status_code, 200)
        args, _ = mock_request.call_args
        self.assertTrue(args[1].endswith("/linked-accounts/idp.acme.com"))

    def test_bare_dot_segments_are_still_rejected(self):
        """The reason the dot was excluded in the first place. These must
        never reach Keycloak: ``requests`` would normalise them away and
        issue the DELETE against the account root."""
        for alias in ("..", "."):
            with self.subTest(alias=alias):
                response, mock_request = self._unlink(alias)
                self.assertEqual(response.status_code, 400)
                mock_request.assert_not_called()

                response, mock_request = self._link_url(alias)
                self.assertEqual(response.status_code, 400)
                mock_request.assert_not_called()

    def test_traversal_and_separators_are_still_rejected(self):
        """A dot in the charset must not become a dot *sequence* with a
        separator: ``/`` stays out, so no interior segment can form."""
        for alias in ("../etc/passwd", "..%2f..", "a/b", "", "with space"):
            with self.subTest(alias=alias):
                response, mock_request = self._unlink(alias)
                self.assertEqual(response.status_code, 400)
                mock_request.assert_not_called()

    def test_an_alias_that_merely_contains_dots_is_fine(self):
        """``..`` is only dangerous as a whole segment -- these are not."""
        for alias in ("a..b", "..leading", "trailing.."):
            with self.subTest(alias=alias):
                response, _ = self._unlink(alias)
                self.assertEqual(response.status_code, 204)


class TestTokensAreNotStashedOnRefusedLogin(TestCase):
    """The IdP accepting a user is not the platform accepting them.

    Between the token exchange and a successful login the callback has
    several 400/401 exits -- no local user under ``AUTO_CREATE_USER=False``,
    required claims missing, validation errors. Stashing the tokens above
    those exits leaves every one of them with a session the account proxy
    treats as signed in, so a caller the deployment just refused can still
    list and revoke Keycloak sessions, unlink IdPs and read credentials.
    """

    TOKENS = {
        "id_token": "idp-id-token",
        "access_token": "idp-access-token",
        "refresh_token": "idp-refresh-token",
    }

    FULL_CLAIMS = {
        "given_name": "Refused",
        "family_name": "User",
        "email": "refused@example.com",
        "preferred_username": "refused",
    }

    def setUp(self):
        self.factory = APIRequestFactory()

    def _run_callback(self, claims):
        """Drive a full auth-code callback; return (response, session)."""
        view = KeycloakOpenIDConnectViewset.as_view({"post": "callback"})
        with (
            patch(
                "oidc.viewsets.OpenIDClient.retrieve_tokens_using_auth_code",
                return_value=dict(self.TOKENS),
            ),
            patch(
                "oidc.viewsets.OpenIDClient.verify_and_decode_id_token",
                return_value=claims,
            ),
        ):
            request = self.factory.post("/", data={"code": "auth-code"})
            request.session = {}
            response = view(request, auth_server="default")
        return response, request.session

    def _assert_no_tokens(self, session):
        for base_key in (
            ACCESS_TOKEN_SESSION_KEY,
            REFRESH_TOKEN_SESSION_KEY,
            ID_TOKEN_SESSION_KEY,
        ):
            self.assertNotIn(token_session_key(base_key, "default"), session)

    @override_settings(
        OPENID_CONNECT_VIEWSET_CONFIG={
            **OPENID_CONNECT_VIEWSET_CONFIG,
            "AUTO_CREATE_USER": False,
        }
    )
    def test_nothing_stashed_when_the_deployment_refuses_to_provision(self):
        """AUTO_CREATE_USER=False is an access-control gate. A caller it
        turns away must not walk off with a working proxy session."""
        response, session = self._run_callback(self.FULL_CLAIMS)

        self.assertEqual(response.status_code, 401)
        self._assert_no_tokens(session)

    def test_nothing_stashed_when_required_claims_are_missing(self):
        """Email-only claims: present so no user-info round-trip happens,
        while first_name stays missing whatever the fallbacks do --
        ``_clean_user_data`` backfills it from last_name and username from
        email, but there is no last_name here -- so this is the hard 400
        exit, not the username form."""
        response, session = self._run_callback({"email": "refused@example.com"})

        self.assertEqual(response.status_code, 400)
        self._assert_no_tokens(session)

    def test_tokens_are_still_stashed_on_a_successful_login(self):
        """The guard: moving the stash must not stop it happening."""
        response, session = self._run_callback(self.FULL_CLAIMS)

        self.assertEqual(response.status_code, 302)
        self.assertEqual(
            session[token_session_key(ACCESS_TOKEN_SESSION_KEY, "default")],
            "idp-access-token",
        )
        self.assertEqual(
            session[token_session_key(REFRESH_TOKEN_SESSION_KEY, "default")],
            "idp-refresh-token",
        )
        self.assertEqual(
            session[token_session_key(ID_TOKEN_SESSION_KEY, "default")],
            "idp-id-token",
        )

    @override_settings(
        OPENID_CONNECT_AUTH_SERVERS={
            **OPENID_CONNECT_AUTH_SERVERS,
            "default": {
                **OPENID_CONNECT_AUTH_SERVERS["default"],
                "ACCOUNT_ENDPOINT": "https://idp.example.com/realms/r/account",
            },
        },
        OPENID_CONNECT_VIEWSET_CONFIG={
            **OPENID_CONNECT_VIEWSET_CONFIG,
            "AUTO_CREATE_USER": False,
        },
    )
    def test_the_account_proxy_refuses_a_session_from_a_refused_callback(self):
        """What the stash actually buys an unprovisioned caller, end to end."""
        response, session = self._run_callback(self.FULL_CLAIMS)
        self.assertEqual(response.status_code, 401)

        proxy_view = KeycloakOpenIDConnectViewset.as_view({"get": "linked_list"})
        proxy_request = self.factory.get("/")
        proxy_request.session = session

        unreached = MagicMock(status_code=200, content=b"[]")
        unreached.json.return_value = []
        with patch(
            "oidc.client.requests.request", return_value=unreached
        ) as mock_request:
            proxy_response = proxy_view(proxy_request, auth_server="default")

        self.assertEqual(proxy_response.status_code, 401)
        mock_request.assert_not_called()

    def test_username_form_round_trip_carries_the_token_pair_through_pending(self):
        """The flow pending slots exist to serve beyond refusal-gating.

        Only the first callback holds the access/refresh pair -- the
        username form re-POSTs just the id_token -- so the pair rides in
        the session as pending across the round trip. It must be invisible
        to the proxy while the form is up (login not yet accepted) and
        active once the resubmit succeeds.
        """
        # No preferred_username claim at all: with USE_EMAIL_USERNAME off
        # (the tests/settings.py default) that leaves exactly {username}
        # missing, which is the 200 username-form path.
        claims = {
            "given_name": "Pend",
            "family_name": "User",
            "email": "pend@example.com",
        }
        with patch(
            "oidc.viewsets.OpenIDClient.verify_and_decode_id_token",
            return_value=claims,
        ):
            view = KeycloakOpenIDConnectViewset.as_view({"post": "callback"})
            with patch(
                "oidc.viewsets.OpenIDClient.retrieve_tokens_using_auth_code",
                return_value=dict(self.TOKENS),
            ):
                first = self.factory.post("/", data={"code": "auth-code"})
                first.session = {}
                first_response = view(first, auth_server="default")

            # The username form is up: not signed in yet.
            self.assertEqual(first_response.status_code, 200)
            self.assertNotIn(
                token_session_key(ACCESS_TOKEN_SESSION_KEY, "default"),
                first.session,
            )

            # The form re-POSTs with only the id_token; same session.
            resubmit = self.factory.post(
                "/?code=stale-code&state=stale-state",
                data={
                    "id_token": "idp-id-token",
                    "username": "pend_chosen",
                    USERNAME_FORM_MARKER_FIELD: USERNAME_FORM_MARKER_VALUE,
                },
            )
            resubmit.session = first.session
            resubmit_response = view(resubmit, auth_server="default")

        self.assertEqual(resubmit_response.status_code, 302)
        self.assertEqual(
            resubmit.session[token_session_key(ACCESS_TOKEN_SESSION_KEY, "default")],
            "idp-access-token",
        )
        self.assertEqual(
            resubmit.session[token_session_key(REFRESH_TOKEN_SESSION_KEY, "default")],
            "idp-refresh-token",
        )


@override_settings(ROOT_URLCONF="tests.keycloak_urls")
class TestReadsAreOriginGated(TestCase):
    """Safe methods enforce the Origin allowlist too — header not required.

    The way a cross-origin page *reads* one of these listings is a
    credentialed CORS fetch against a deployment whose CORS reflects
    arbitrary origins — and that fetch always carries ``Origin``. Checking
    it server-side closes the leak the old docstring could only warn about.

    The custom header stays a write-only requirement: markup GETs
    (``<img>``, ``<script>``) cannot read JSON responses anyway, so a
    header check on reads adds nothing the Origin check does not — and the
    SPA deliberately omits the header on GET, with a client-side test
    pinning exactly that.
    """

    def setUp(self):
        self.factory = APIRequestFactory()
        self.perm = IsCsrfSafeAccountRequest()
        self.view = SimpleNamespace(kwargs={"auth_server": "default"})

    def test_get_from_an_untrusted_origin_is_denied(self):
        request = self.factory.get("/", HTTP_ORIGIN="https://evil.example")
        self.assertFalse(self.perm.has_permission(request, self.view))

    def test_get_without_origin_is_allowed(self):
        """Same-origin GETs (navigation, same-origin fetch) omit Origin."""
        self.assertTrue(self.perm.has_permission(self.factory.get("/"), self.view))

    def test_get_from_own_host_is_allowed(self):
        request = self.factory.get("/", HTTP_ORIGIN="http://testserver")
        self.assertTrue(self.perm.has_permission(request, self.view))

    @override_settings(
        OPENID_CONNECT_AUTH_SERVERS={
            **OPENID_CONNECT_AUTH_SERVERS,
            "default": {
                **OPENID_CONNECT_AUTH_SERVERS["default"],
                "LOGIN_REDIRECT_ALLOWED_HOSTS": ["app.example.com"],
            },
        }
    )
    def test_get_from_the_allowlisted_spa_needs_no_header(self):
        """Pins the read contract the SPA relies on: trusted origin,
        no ``X-Ona-Account-Request``, still allowed."""
        request = self.factory.get("/", HTTP_ORIGIN="https://app.example.com")
        self.assertTrue(self.perm.has_permission(request, self.view))

    def test_writes_still_need_the_header_even_from_a_trusted_origin(self):
        """The origin gate joining the safe path must not relax the write
        path: same-origin without the header stays refused."""
        request = self.factory.post("/", HTTP_ORIGIN="http://testserver")
        self.assertFalse(self.perm.has_permission(request, self.view))

    @override_settings(
        OPENID_CONNECT_AUTH_SERVERS={
            **OPENID_CONNECT_AUTH_SERVERS,
            "default": {
                **OPENID_CONNECT_AUTH_SERVERS["default"],
                "ACCOUNT_ENDPOINT": "https://idp.example.com/realms/r/account",
            },
        },
        OPENID_CONNECT_VIEWSET_CONFIG=OPENID_CONNECT_VIEWSET_CONFIG,
    )
    def test_a_cross_origin_read_never_reaches_keycloak(self):
        """End to end: even with hostile CORS reflecting the attacker's
        origin, the listing is never fetched, so there is nothing for the
        browser to hand over.

        as_view is given the permission explicitly: calling an @action
        method this way bypasses the decorator's kwargs (the router applies
        those), which would silently test AllowAny instead."""
        view = KeycloakOpenIDConnectViewset.as_view(
            {"get": "linked_list"},
            authentication_classes=[],
            permission_classes=[IsCsrfSafeAccountRequest],
        )
        request = self.factory.get("/", HTTP_ORIGIN="https://evil.example")
        request.session = {"oidc_access_token:default": "t"}

        unreached = MagicMock(status_code=200, content=b"[]")
        unreached.json.return_value = []
        with patch(
            "oidc.client.requests.request", return_value=unreached
        ) as mock_request:
            response = view(request, auth_server="default")

        self.assertEqual(response.status_code, 403)
        mock_request.assert_not_called()


@override_settings(
    OPENID_CONNECT_AUTH_SERVERS={
        **OPENID_CONNECT_AUTH_SERVERS,
        "default": {
            **OPENID_CONNECT_AUTH_SERVERS["default"],
            "ACCOUNT_ENDPOINT": "https://idp.example.com/realms/r/account",
        },
    },
    OPENID_CONNECT_VIEWSET_CONFIG=OPENID_CONNECT_VIEWSET_CONFIG,
)
class TestPendingTokensBelongToOneFlow(TestCase):
    """Pending slots are per-provider, but a session can run two logins.

    Two tabs, one Django session: only the tab that reaches the username
    form keeps a pending access/refresh pair, and the form re-POST carries
    just an id_token. If promotion pairs that id_token with whatever pair
    happens to be pending, the SPA ends up signed in as one identity while
    the account proxy authenticates to Keycloak as another.
    """

    def setUp(self):
        self.factory = APIRequestFactory()

    def _callback(self, session, claims, tokens):
        view = KeycloakOpenIDConnectViewset.as_view({"post": "callback"})
        with (
            patch(
                "oidc.viewsets.OpenIDClient.retrieve_tokens_using_auth_code",
                return_value=dict(tokens),
            ),
            patch(
                "oidc.viewsets.OpenIDClient.verify_and_decode_id_token",
                return_value=claims,
            ),
        ):
            request = self.factory.post("/", data={"code": "auth-code"})
            request.session = session
            response = view(request, auth_server="default")
        return response

    def _resubmit(self, session, claims, id_token, username):
        view = KeycloakOpenIDConnectViewset.as_view({"post": "callback"})
        with patch(
            "oidc.viewsets.OpenIDClient.verify_and_decode_id_token",
            return_value=claims,
        ):
            request = self.factory.post(
                "/",
                data={
                    "id_token": id_token,
                    "username": username,
                    USERNAME_FORM_MARKER_FIELD: USERNAME_FORM_MARKER_VALUE,
                },
            )
            request.session = session
            response = view(request, auth_server="default")
        return response

    def test_an_interleaved_flow_cannot_donate_its_token_pair(self):
        """Both tabs must reach the *username form*, not just one.

        Only the form exit parks a pair, so an interleaving where the second
        tab takes a hard refusal parks nothing and there is no mismatched
        pair to reject — such a test passes with the owner check deleted.
        Here tab B parks over tab A's slots, so A's resubmit is handed a
        pair belonging to B and must refuse it.
        """
        session = {}
        x_claims = {
            "given_name": "Ex",
            "family_name": "User",
            "email": "x@example.com",
        }
        y_claims = {
            "given_name": "Why",
            "family_name": "User",
            "email": "y@example.com",
        }

        # Tab A: identity X. Derived username "x" is under 3 chars -> form.
        first = self._callback(
            session,
            x_claims,
            {
                "id_token": "id-token-X",
                "access_token": "access-X",
                "refresh_token": "refresh-X",
            },
        )
        self.assertEqual(first.status_code, 200)

        # Tab B: identity Y, same session, also lands on the form and parks
        # over A's slots.
        second = self._callback(
            session,
            y_claims,
            {
                "id_token": "id-token-Y",
                "access_token": "access-Y",
                "refresh_token": "refresh-Y",
            },
        )
        self.assertEqual(second.status_code, 200)
        self.assertEqual(
            session.get(pending_token_session_key(ACCESS_TOKEN_SESSION_KEY, "default")),
            "access-Y",
            "tab B should have parked over tab A -- otherwise this test proves nothing",
        )

        # Tab A completes. Carries only X's id_token; the parked pair is B's.
        done = self._resubmit(session, x_claims, "id-token-X", "ex_chosen")
        self.assertEqual(done.status_code, 302)

        # Signed in as X, so the proxy must not hold Y's credentials. Assert
        # the slots are absent outright, not merely "not Y's".
        self.assertEqual(
            session.get(token_session_key(ID_TOKEN_SESSION_KEY, "default")),
            "id-token-X",
        )
        self.assertNotIn(
            token_session_key(ACCESS_TOKEN_SESSION_KEY, "default"), session
        )
        self.assertNotIn(
            token_session_key(REFRESH_TOKEN_SESSION_KEY, "default"), session
        )

    def test_a_flow_without_a_refresh_token_cannot_inherit_one(self):
        """The park must be atomic. If a second flow's token response has no
        refresh token, skipping that slot would leave the first flow's
        refresh token behind under the *second* flow's owner tag — waving a
        mispaired credential through the very check meant to catch it."""
        session = {}
        x_claims = {
            "given_name": "Ex",
            "family_name": "User",
            "email": "x@example.com",
        }
        y_claims = {
            "given_name": "Why",
            "family_name": "User",
            "email": "y@example.com",
        }

        self._callback(
            session,
            x_claims,
            {
                "id_token": "id-token-X",
                "access_token": "access-X",
                "refresh_token": "refresh-X",
            },
        )
        # Tab B: access token but no refresh token.
        self._callback(
            session,
            y_claims,
            {"id_token": "id-token-Y", "access_token": "access-Y"},
        )

        done = self._resubmit(session, y_claims, "id-token-Y", "why_chosen")
        self.assertEqual(done.status_code, 302)
        self.assertNotIn(
            token_session_key(REFRESH_TOKEN_SESSION_KEY, "default"),
            session,
            "flow Y inherited flow X's refresh token",
        )

    def test_a_dropped_pair_does_not_leave_an_earlier_logins_pair_active(self):
        """Refusing a mismatched pair must also clear whatever a previous
        login left in the active slots, or the new id_token ends up beside
        the old pair — the same split, reached from the other side."""
        session = {}
        z_claims = {
            "given_name": "Zed",
            "family_name": "User",
            "email": "zed@example.com",
        }
        # A completed login leaves an active pair behind.
        self._callback(
            session,
            z_claims,
            {
                "id_token": "id-token-Z",
                "access_token": "access-Z",
                "refresh_token": "refresh-Z",
            },
        )
        self.assertEqual(
            session[token_session_key(ACCESS_TOKEN_SESSION_KEY, "default")], "access-Z"
        )

        # Two interleaved form flows; the second parks over the first.
        x_claims = {
            "given_name": "Ex",
            "family_name": "User",
            "email": "x@example.com",
        }
        y_claims = {
            "given_name": "Why",
            "family_name": "User",
            "email": "y@example.com",
        }
        self._callback(
            session,
            x_claims,
            {
                "id_token": "id-token-X",
                "access_token": "access-X",
                "refresh_token": "refresh-X",
            },
        )
        self._callback(
            session,
            y_claims,
            {
                "id_token": "id-token-Y",
                "access_token": "access-Y",
                "refresh_token": "refresh-Y",
            },
        )

        done = self._resubmit(session, x_claims, "id-token-X", "ex_chosen")
        self.assertEqual(done.status_code, 302)
        self.assertNotIn(
            token_session_key(ACCESS_TOKEN_SESSION_KEY, "default"),
            session,
            "Z's pair survived beside X's id_token",
        )

    def test_an_abandoned_form_does_not_leave_a_pair_parked_forever(self):
        """Nothing else clears a parked pair for a login that was never
        finished, so the next success in the session has to."""
        session = {}
        self._callback(
            session,
            {"given_name": "Ex", "family_name": "User", "email": "x@example.com"},
            {
                "id_token": "id-token-X",
                "access_token": "access-X",
                "refresh_token": "refresh-X",
            },
        )
        self.assertIn(
            pending_token_session_key(REFRESH_TOKEN_SESSION_KEY, "default"), session
        )

        # A different, complete login in the same session.
        self._callback(
            session,
            {
                "given_name": "Solo",
                "family_name": "User",
                "email": "solo@example.com",
            },
            {
                "id_token": "id-token-S",
                "access_token": "access-S",
                "refresh_token": "refresh-S",
            },
        )

        for base_key in (
            ID_TOKEN_SESSION_KEY,
            ACCESS_TOKEN_SESSION_KEY,
            REFRESH_TOKEN_SESSION_KEY,
        ):
            self.assertNotIn(
                pending_token_session_key(base_key, "default"),
                session,
                "abandoned pair still parked",
            )

    def test_a_hard_refusal_leaves_no_credentials_at_rest(self):
        """A refused caller never logs out, so nothing else will ever clear
        their stash. It must not be written in the first place."""
        session = {}
        response = self._callback(
            session,
            {"email": "y@example.com"},
            {
                "id_token": "id-token-Y",
                "access_token": "access-Y",
                "refresh_token": "refresh-Y",
            },
        )

        self.assertEqual(response.status_code, 400)
        self.assertEqual(
            [
                v
                for v in session.values()
                if "access-Y" in str(v) or "refresh-Y" in str(v)
            ],
            [],
            f"refresh/access token left at rest in session: {session}",
        )

    def test_the_ordinary_form_round_trip_still_works(self):
        """Guard: the flow pending slots exist for must keep working."""
        session = {}
        # A one-character local part: USE_EMAIL_USERNAME derives "s", which
        # fails the 3-char username regex, so only {username} is missing --
        # the form exit rather than a straight success.
        claims = {
            "given_name": "Solo",
            "family_name": "User",
            "email": "s@example.com",
        }
        first = self._callback(
            session,
            claims,
            {
                "id_token": "id-token-S",
                "access_token": "access-S",
                "refresh_token": "refresh-S",
            },
        )
        self.assertEqual(first.status_code, 200)

        done = self._resubmit(session, claims, "id-token-S", "solo_chosen")
        self.assertEqual(done.status_code, 302)
        self.assertEqual(
            session[token_session_key(ACCESS_TOKEN_SESSION_KEY, "default")],
            "access-S",
        )
        self.assertEqual(
            session[token_session_key(REFRESH_TOKEN_SESSION_KEY, "default")],
            "refresh-S",
        )


class TestProviderAliasAnchoring(TestCase):
    """``$`` also matches before a trailing newline, so an alias validator
    anchored with ``$`` does not actually pin the whole string."""

    def test_a_trailing_newline_cannot_smuggle_a_dot_segment(self):
        from oidc.keycloak import _is_valid_provider_alias

        for alias in ("..\n", ".\n", "google\n"):
            with self.subTest(alias=alias):
                self.assertFalse(_is_valid_provider_alias(alias))

    def test_ordinary_aliases_still_pass(self):
        from oidc.keycloak import _is_valid_provider_alias

        for alias in ("google", "idp.acme.com", "MyIdP", "a..b"):
            with self.subTest(alias=alias):
                self.assertTrue(_is_valid_provider_alias(alias))


@override_settings(
    OPENID_CONNECT_AUTH_SERVERS=OPENID_CONNECT_AUTH_SERVERS,
    OPENID_CONNECT_VIEWSET_CONFIG=OPENID_CONNECT_VIEWSET_CONFIG,
)
class TestLogoutClearsPreNamespacingTokens(TestCase):
    """A session established before the per-provider rename holds bare
    ``oidc_id_token`` etc. Nothing reads those any more, but only
    ``logout`` can remove them -- the session is flushed just under
    ``USE_AUTH_BACKEND``, off by default -- so without a write-side sweep
    they outlive every sign-out until the session itself expires."""

    def setUp(self):
        self.factory = APIRequestFactory()

    def test_logout_removes_the_legacy_unscoped_keys(self):
        view = KeycloakOpenIDConnectViewset.as_view({"get": "logout"})
        request = self.factory.get("/")
        request.session = {
            "oidc_id_token": "legacy.id",
            "oidc_access_token": "legacy.access",
            "oidc_refresh_token": "legacy.refresh",
            "unrelated": "keep",
        }

        response = view(request, auth_server="default")

        self.assertEqual(response.status_code, 302)
        for legacy in ("oidc_id_token", "oidc_access_token", "oidc_refresh_token"):
            self.assertNotIn(legacy, request.session)
        self.assertEqual(request.session.get("unrelated"), "keep")

    def test_a_legacy_id_token_is_not_replayed_as_a_hint(self):
        """Removing it must not resurrect it as ``id_token_hint`` -- that
        would be a fallback *read*, which is exactly what the namespacing
        refuses."""
        view = KeycloakOpenIDConnectViewset.as_view({"get": "logout"})
        request = self.factory.get("/")
        request.session = {"oidc_id_token": "legacy.id"}

        response = view(request, auth_server="default")

        self.assertNotIn("id_token_hint", response.url)
        self.assertNotIn("legacy.id", response.url)


@override_settings(
    OPENID_CONNECT_AUTH_SERVERS=OPENID_CONNECT_AUTH_SERVERS,
    OPENID_CONNECT_VIEWSET_CONFIG=OPENID_CONNECT_VIEWSET_CONFIG,
)
class TestCallbackDoesNotLogCredentials(TestCase):
    """The id_token must never reach the application log.

    ``callback`` accepts an id_token straight from the POST body on the
    username-form path (``from_username_form=1``), so a token in the log is
    not merely sensitive at rest -- anyone who can read logs can replay it
    and obtain a session as that user, and with the account proxy mixed in,
    their Keycloak account too.
    """

    SECRET_TOKEN = "HEADER.SECRET_TOKEN_MATERIAL.SIGNATURE"

    def setUp(self):
        self.factory = APIRequestFactory()

    def _run(self, claims, data=None):
        view = UserModelOpenIDConnectViewset.as_view({"post": "callback"})
        with patch(
            "oidc.viewsets.OpenIDClient.verify_and_decode_id_token",
            return_value=claims,
        ):
            request = self.factory.post(
                "/", data={"id_token": self.SECRET_TOKEN, **(data or {})}
            )
            request.session = {}
            with self.assertLogs("oidc.viewsets", level="DEBUG") as captured:
                # A log line is not guaranteed on every path; emit one so
                # assertLogs always has something and the test is about
                # *what* was logged, not whether anything was.
                logging.getLogger("oidc.viewsets").info("probe")
                response = view(request, auth_server="default")
        return response, "\n".join(captured.output)

    def test_the_uniqueness_conflict_path_does_not_log_the_id_token(self):
        # Username collides, email does not -- an email match would find the
        # existing user and log straight in, never reaching the conflict.
        User.objects.create(username="taken", email="incumbent@example.com")

        response, logged = self._run(
            {
                "given_name": "Taken",
                "family_name": "User",
                "email": "newcomer@example.com",
                "preferred_username": "taken",
            }
        )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data["error"], "Username field is already in use.")
        self.assertNotIn(self.SECRET_TOKEN, logged)
        self.assertNotIn("SECRET_TOKEN_MATERIAL", logged)

    def test_a_field_validation_failure_does_not_forge_log_lines(self):
        """The rejected value is caller-supplied; interpolated raw, a
        newline in it would forge an extra log line."""
        response, logged = self._run(
            {
                "given_name": "Bad",
                "family_name": "User",
                "email": "bad@example.com",
                "preferred_username": "ok_username",
            },
            data={
                "username": "x\nINFO:oidc.viewsets:forged line",
                USERNAME_FORM_MARKER_FIELD: USERNAME_FORM_MARKER_VALUE,
            },
        )

        self.assertNotIn(self.SECRET_TOKEN, logged)
        # The newline must be escaped by %r rather than starting a new line.
        for line in logged.splitlines():
            self.assertNotEqual(line.strip(), "forged line")


class TestCredentialBearingSessionHardening(TestCase):
    """Guards on the session that now carries access and refresh tokens.

    Before this feature the session held only an id_token the browser had
    already seen. Storing a *refresh* token there raises the stakes on two
    Django-level choices the library was previously indifferent to.
    """

    def setUp(self):
        self.factory = APIRequestFactory()

    @override_settings(
        OPENID_CONNECT_AUTH_SERVERS=OPENID_CONNECT_AUTH_SERVERS,
        OPENID_CONNECT_VIEWSET_CONFIG=OPENID_CONNECT_VIEWSET_CONFIG,
        SESSION_ENGINE="django.contrib.sessions.backends.signed_cookies",
    )
    def test_a_proxy_viewset_refuses_cookie_backed_sessions(self):
        """Signed-cookie sessions are signed but not encrypted, and survive
        logout because there is no server-side record to delete."""
        with self.assertRaises(ImproperlyConfigured) as ctx:
            KeycloakOpenIDConnectViewset()
        self.assertIn("signed_cookies", str(ctx.exception))
        self.assertIn("SESSION_ENGINE", str(ctx.exception))

    @override_settings(
        OPENID_CONNECT_AUTH_SERVERS=OPENID_CONNECT_AUTH_SERVERS,
        OPENID_CONNECT_VIEWSET_CONFIG=OPENID_CONNECT_VIEWSET_CONFIG,
        SESSION_ENGINE="django.contrib.sessions.backends.signed_cookies",
    )
    def test_a_viewset_that_stashes_nothing_is_unaffected(self):
        """The base viewset keeps only the id_token, which the browser
        already holds -- refusing cookie sessions there would be gratuitous.
        """
        UserModelOpenIDConnectViewset()

    @override_settings(
        OPENID_CONNECT_AUTH_SERVERS=OPENID_CONNECT_AUTH_SERVERS,
        OPENID_CONNECT_VIEWSET_CONFIG=OPENID_CONNECT_VIEWSET_CONFIG,
    )
    def test_the_session_key_is_rotated_when_tokens_are_written(self):
        """Session fixation: the id the request arrived with must not be the
        one that ends up holding the tokens."""
        from django.contrib.sessions.backends.db import SessionStore

        session = SessionStore()
        session.create()
        original_key = session.session_key

        view = KeycloakOpenIDConnectViewset.as_view({"post": "callback"})
        with (
            patch(
                "oidc.viewsets.OpenIDClient.retrieve_tokens_using_auth_code",
                return_value={
                    "id_token": "idp-id-token",
                    "access_token": "idp-access-token",
                    "refresh_token": "idp-refresh-token",
                },
            ),
            patch(
                "oidc.viewsets.OpenIDClient.verify_and_decode_id_token",
                return_value={
                    "given_name": "Rot",
                    "family_name": "User",
                    "email": "rot@example.com",
                    "preferred_username": "rotuser",
                },
            ),
        ):
            request = self.factory.post("/", data={"code": "auth-code"})
            request.session = session
            response = view(request, auth_server="default")

        self.assertEqual(response.status_code, 302)
        self.assertIsNotNone(session.session_key)
        self.assertNotEqual(session.session_key, original_key)
        # Rotation must not lose the tokens it exists to protect.
        self.assertEqual(
            session[token_session_key(ACCESS_TOKEN_SESSION_KEY, "default")],
            "idp-access-token",
        )


class TestOutboundRequestsHaveTimeouts(TestCase):
    """``requests`` waits forever by default, so an IdP that accepts the
    connection then stalls pins the worker. Every proxy call and every
    callback goes through this client."""

    @override_settings(
        OPENID_CONNECT_AUTH_SERVERS={
            **OPENID_CONNECT_AUTH_SERVERS,
            "default": {
                **OPENID_CONNECT_AUTH_SERVERS["default"],
                "ACCOUNT_ENDPOINT": "https://idp.example.com/realms/r/account",
            },
        }
    )
    def test_the_account_request_passes_a_timeout(self):
        client = OpenIDClient("default")
        upstream = MagicMock(status_code=200, content=b"{}")
        upstream.json.return_value = {}
        with patch(
            "oidc.client.requests.request", return_value=upstream
        ) as mock_request:
            client.request_keycloak_account("tok", "GET", "/sessions")
        self.assertIsNotNone(mock_request.call_args.kwargs.get("timeout"))

    @override_settings(OPENID_CONNECT_AUTH_SERVERS=OPENID_CONNECT_AUTH_SERVERS)
    def test_the_token_refresh_passes_a_timeout(self):
        client = OpenIDClient("default")
        upstream = MagicMock(status_code=200)
        upstream.json.return_value = {"access_token": "a"}
        with patch("oidc.client.requests.post", return_value=upstream) as mock_post:
            client.refresh_access_token("refresh")
        self.assertIsNotNone(mock_post.call_args.kwargs.get("timeout"))

    @override_settings(
        OPENID_CONNECT_AUTH_SERVERS={
            **OPENID_CONNECT_AUTH_SERVERS,
            "default": {
                **OPENID_CONNECT_AUTH_SERVERS["default"],
                "REQUEST_TIMEOUT": (1, 2),
            },
        }
    )
    def test_the_timeout_is_configurable_per_auth_server(self):
        self.assertEqual(OpenIDClient("default").request_timeout, (1, 2))


class TestSessionBackendDeployCheck(TestCase):
    """The per-request ``ImproperlyConfigured`` only reaches the first user
    who tries to sign in. The deploy check catches it at ``manage.py check``
    instead, which is where a misconfiguration this consequential belongs.
    """

    @override_settings(
        SESSION_ENGINE="django.contrib.sessions.backends.signed_cookies",
        OPENID_CONNECT_VIEWSET_CONFIG={
            **OPENID_CONNECT_VIEWSET_CONFIG,
            "VIEWSET_CLASS": "oidc.keycloak.KeycloakOpenIDConnectViewset",
        },
    )
    def test_cookie_sessions_plus_a_token_stashing_viewset_is_an_error(self):
        errors = check_session_backend_can_hold_tokens(None)
        self.assertEqual([e.id for e in errors], ["oidc.E001"])
        self.assertIn("signed_cookies", errors[0].msg)

    @override_settings(
        SESSION_ENGINE="django.contrib.sessions.backends.signed_cookies",
        OPENID_CONNECT_VIEWSET_CONFIG=OPENID_CONNECT_VIEWSET_CONFIG,
    )
    def test_cookie_sessions_alone_are_fine(self):
        """The default viewset keeps only the id_token, which the browser
        already holds -- flagging that would be gratuitous."""
        self.assertEqual(check_session_backend_can_hold_tokens(None), [])

    @override_settings(
        SESSION_ENGINE="django.contrib.sessions.backends.cached_db",
        OPENID_CONNECT_VIEWSET_CONFIG={
            **OPENID_CONNECT_VIEWSET_CONFIG,
            "VIEWSET_CLASS": "oidc.keycloak.KeycloakOpenIDConnectViewset",
        },
    )
    def test_a_server_side_backend_is_fine(self):
        self.assertEqual(check_session_backend_can_hold_tokens(None), [])

    @override_settings(
        OPENID_CONNECT_VIEWSET_CONFIG={
            **OPENID_CONNECT_VIEWSET_CONFIG,
            "VIEWSET_CLASS": "oidc.keycloak.KeycloakOpenIDConnectViewset",
        },
    )
    def test_the_django_default_backend_is_fine(self):
        """SESSION_ENGINE unset must not be read as the cookie backend."""
        self.assertEqual(check_session_backend_can_hold_tokens(None), [])

    @override_settings(
        SESSION_ENGINE="django.contrib.sessions.backends.signed_cookies",
        OPENID_CONNECT_VIEWSET_CONFIG={
            **OPENID_CONNECT_VIEWSET_CONFIG,
            "VIEWSET_CLASS": "nonexistent.module.Viewset",
        },
    )
    def test_an_unresolvable_viewset_is_left_to_its_own_error(self):
        """Not this check's job to report a broken VIEWSET_CLASS, and it
        must not mask it by raising from here."""
        self.assertEqual(check_session_backend_can_hold_tokens(None), [])


@override_settings(
    OPENID_CONNECT_AUTH_SERVERS=OPENID_CONNECT_AUTH_SERVERS,
    OPENID_CONNECT_VIEWSET_CONFIG={
        **OPENID_CONNECT_VIEWSET_CONFIG,
        "USE_AUTH_BACKEND": True,
    },
)
class TestTokensSurviveDjangoLogin(TestCase):
    """Django's ``login()`` flushes the session when a *different* user was
    already authenticated in it. Anything written before that call is gone.

    Reachable without any misuse: a browser still holding a session for one
    account runs the OIDC flow and picks another at the IdP. The sign-in
    succeeds, so nothing looks wrong -- but the proxy answers 401 to every
    call and logout has no ``id_token_hint``, and only a full sign-out
    clears it. ``USE_AUTH_BACKEND`` is off in the library default but on in
    the deployment this proxy was built for.
    """

    TOKENS = {
        "id_token": "idp-id-token",
        "access_token": "idp-access-token",
        "refresh_token": "idp-refresh-token",
    }

    def setUp(self):
        self.factory = APIRequestFactory()

    def _session_authenticated_as(self, user):
        from django.contrib.auth import (
            BACKEND_SESSION_KEY,
            HASH_SESSION_KEY,
            SESSION_KEY,
        )
        from django.contrib.sessions.backends.db import SessionStore

        session = SessionStore()
        session[SESSION_KEY] = str(user.pk)
        session[BACKEND_SESSION_KEY] = "django.contrib.auth.backends.ModelBackend"
        session[HASH_SESSION_KEY] = user.get_session_auth_hash()
        session.save()
        return session

    def test_signing_in_as_a_second_user_keeps_the_new_tokens(self):
        incumbent = User.objects.create(
            username="incumbent", email="incumbent@example.com"
        )
        session = self._session_authenticated_as(incumbent)

        view = KeycloakOpenIDConnectViewset.as_view({"post": "callback"})
        with (
            patch(
                "oidc.viewsets.OpenIDClient.retrieve_tokens_using_auth_code",
                return_value=dict(self.TOKENS),
            ),
            patch(
                "oidc.viewsets.OpenIDClient.verify_and_decode_id_token",
                return_value={
                    "given_name": "New",
                    "family_name": "Comer",
                    "email": "newcomer@example.com",
                    "preferred_username": "newcomer",
                },
            ),
        ):
            request = self.factory.post("/", data={"code": "auth-code"})
            request.session = session
            response = view(request, auth_server="default")

        self.assertEqual(response.status_code, 302)
        self.assertEqual(
            session.get(token_session_key(ACCESS_TOKEN_SESSION_KEY, "default")),
            "idp-access-token",
            "login() flushed the session after the tokens were written",
        )
        self.assertEqual(
            session.get(token_session_key(REFRESH_TOKEN_SESSION_KEY, "default")),
            "idp-refresh-token",
        )
        # Without this, logout falls back to a bare end-session URL and
        # Keycloak shows its confirm screen.
        self.assertEqual(
            session.get(token_session_key(ID_TOKEN_SESSION_KEY, "default")),
            "idp-id-token",
        )

    @override_settings(
        OPENID_CONNECT_AUTH_SERVERS={
            **OPENID_CONNECT_AUTH_SERVERS,
            "default": {
                **OPENID_CONNECT_AUTH_SERVERS["default"],
                "REQUEST_TIMEOUT": [5, 15],
            },
        }
    )
    def test_a_list_from_json_or_yaml_settings_is_accepted(self):
        """``requests`` special-cases tuple only, so the natural serialised
        form of the documented value is the one shape that would break."""
        self.assertEqual(OpenIDClient("default").request_timeout, (5.0, 15.0))

    @override_settings(
        OPENID_CONNECT_AUTH_SERVERS={
            **OPENID_CONNECT_AUTH_SERVERS,
            "default": {
                **OPENID_CONNECT_AUTH_SERVERS["default"],
                "REQUEST_TIMEOUT": "10",
            },
        }
    )
    def test_a_string_from_an_env_var_is_accepted(self):
        self.assertEqual(OpenIDClient("default").request_timeout, 10.0)

    @override_settings(
        OPENID_CONNECT_AUTH_SERVERS={
            **OPENID_CONNECT_AUTH_SERVERS,
            "default": {
                **OPENID_CONNECT_AUTH_SERVERS["default"],
                "REQUEST_TIMEOUT": None,
            },
        }
    )
    def test_none_is_refused_rather_than_restoring_an_unbounded_wait(self):
        with self.assertRaises(ImproperlyConfigured) as ctx:
            OpenIDClient("default")
        self.assertIn("REQUEST_TIMEOUT", str(ctx.exception))

    @override_settings(
        OPENID_CONNECT_AUTH_SERVERS={
            **OPENID_CONNECT_AUTH_SERVERS,
            "default": {
                **OPENID_CONNECT_AUTH_SERVERS["default"],
                "REQUEST_TIMEOUT": (1, 2, 3),
            },
        }
    )
    def test_a_malformed_pair_names_the_setting(self):
        with self.assertRaises(ImproperlyConfigured) as ctx:
            OpenIDClient("default")
        self.assertIn("REQUEST_TIMEOUT", str(ctx.exception))
        self.assertIn("default", str(ctx.exception))
