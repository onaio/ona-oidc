"""
Tests for the OpenID Client
"""

import copy
import json
import os
import time
from datetime import timedelta
from urllib.parse import parse_qs, urlparse

from django.conf import settings
from django.contrib.auth import get_user_model
from django.core.cache import cache
from django.core.exceptions import ImproperlyConfigured
from django.template import TemplateDoesNotExist
from django.test import TestCase
from django.test.utils import override_settings
from django.utils import timezone
from django.views.debug import SafeExceptionReporterFilter

import jwt
import requests
from mock import MagicMock, patch
from rest_framework.test import APIRequestFactory

from oidc.client import (
    ID_TOKEN_LEEWAY_SECONDS,
    REDIRECT_AFTER_AUTH,
    NoJSONWebKeyFound,
    NonceVerificationFailed,
    OpenIDClient,
    TokenVerificationFailed,
    state_cache_key,
)
from oidc.viewsets import (
    DEFAULT_USERNAME_HELP_TEXT,
    DEFAULT_USERNAME_PATTERN,
    LOGIN_CONTINUATION_FIELD,
    USERNAME_FORM_MARKER_FIELD,
    USERNAME_FORM_MARKER_VALUE,
    BaseOpenIDConnectViewset,
    UserModelOpenIDConnectViewset,
)
from tests.error_reports import escaped_frames, reported_locals

User = get_user_model()

ID_TOKEN = "sadsdaio3209lkasdlkas0d.sdojdsiad.iosdadia"


def stash_login_continuation(
    decoded_id_token: dict, auth_server="default", state=None
) -> str:
    """Stash a verified ID token the way a username-form render does."""
    viewset = UserModelOpenIDConnectViewset()
    return viewset._stash_login_continuation(
        OpenIDClient(auth_server),
        ID_TOKEN,
        decoded_id_token,
        viewset.map_claims_to_model_field(decoded_id_token),
        state,
    )


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
        # These tests predate browser binding and drive the callback
        # directly; binding has its own test class below.
        "ENFORCE_BROWSER_BINDING": False,
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
        "ENFORCE_BROWSER_BINDING": False,
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

    def test_username_form_logs_the_missing_field(self):
        """Rendering the username form logs which claim was missing"""
        view = UserModelOpenIDConnectViewset.as_view({"post": "callback"})
        with (
            patch(
                "oidc.viewsets.OpenIDClient.verify_and_decode_id_token",
                return_value={"given_name": "bob", "email": "bob@example.com"},
            ),
            self.assertLogs("oidc.viewsets", level="INFO") as logs,
        ):
            response = view(
                self.factory.post("/", data={"id_token": ID_TOKEN}),
                auth_server="default",
            )

        self.assertEqual(response.template_name, "oidc/oidc_user_data_entry.html")
        self.assertIn("Rendering the username form: missing username", logs.output[-1])

    @override_settings(
        OPENID_CONNECT_VIEWSET_CONFIG={
            **OPENID_CONNECT_VIEWSET_CONFIG,
            "USE_EMAIL_USERNAME": False,
        }
    )
    def test_username_form_json_resubmit_uses_the_chosen_username(self):
        """A JSON re-submit of the username form creates the user with the
        posted username. It used to render the form again."""
        claims = {"given_name": "ivan", "family_name": "User", "email": "i@example.com"}
        view = UserModelOpenIDConnectViewset.as_view({"post": "callback"})

        def resubmit(username):
            data = {
                LOGIN_CONTINUATION_FIELD: stash_login_continuation(claims),
                "username": username,
                USERNAME_FORM_MARKER_FIELD: USERNAME_FORM_MARKER_VALUE,
            }
            request = self.factory.post("/", data=data, format="json")
            return view(request, auth_server="default")

        # A username that is not a string is ignored, so the form comes back.
        response = resubmit(["ivan_list"])
        self.assertEqual(response.template_name, "oidc/oidc_user_data_entry.html")

        response = resubmit("ivan_chosen")
        self.assertEqual(response.status_code, 302)
        self.assertTrue(User.objects.filter(username="ivan_chosen").exists())

    @override_settings(
        OPENID_CONNECT_VIEWSET_CONFIG={
            **OPENID_CONNECT_VIEWSET_CONFIG,
            "USE_EMAIL_USERNAME": False,
        }
    )
    def test_userinfo_timeout_returns_retry_error(self):
        """A userinfo request that times out gets the 401 retry page, not a
        500, and the log names the reason"""
        view = UserModelOpenIDConnectViewset.as_view({"post": "callback"})
        with (
            patch(
                "oidc.viewsets.OpenIDClient.retrieve_tokens_using_auth_code",
                return_value={"id_token": ID_TOKEN, "access_token": "at"},
            ),
            patch(
                "oidc.viewsets.OpenIDClient.verify_and_decode_id_token",
                return_value={"given_name": "erin", "family_name": "User"},
            ),
            patch(
                "oidc.viewsets.OpenIDClient.validate_access_token",
                return_value=True,
            ),
            patch(
                "oidc.client.requests.get", side_effect=requests.Timeout("timed out")
            ) as mock_get,
            self.assertLogs("oidc.viewsets", level="WARNING") as logs,
        ):
            response = view(
                self.factory.post("/", data={"code": "SplxlOBeZQQYbYS6WxSbIA"}),
                auth_server="default",
            )

        mock_get.assert_called_once()
        self.assertEqual(response.status_code, 401)
        self.assertEqual(response.template_name, "oidc/oidc_unrecoverable_error.html")
        self.assertIn("Userinfo request failed: Timeout", logs.output[0])

    @override_settings(OPENID_CONNECT_VIEWSET_CONFIG=OPENID_CONNECT_VIEWSET_CONFIG)
    def test_username_form_resubmit_uses_the_stashed_state(self):
        """
        The re-submit takes ``state`` from the continuation, not the form
        body, so it stays bound to the login that rendered the form.
        """
        stashed_state, posted_state = "stashed-state", "posted-state"
        cache.set(state_cache_key(stashed_state), "stashed-code-verifier")
        cache.set(state_cache_key(posted_state), "posted-code-verifier")
        continuation = stash_login_continuation(
            {
                "given_name": "ivan",
                "family_name": "User",
                "email": "ivan@example.com",
            },
            state=stashed_state,
        )
        view = UserModelOpenIDConnectViewset.as_view({"post": "callback"})
        response = view(
            self.factory.post(
                "/",
                data={
                    LOGIN_CONTINUATION_FIELD: continuation,
                    "username": "ivan_chosen",
                    "state": posted_state,
                    USERNAME_FORM_MARKER_FIELD: USERNAME_FORM_MARKER_VALUE,
                },
            ),
            auth_server="default",
        )

        self.assertEqual(response.status_code, 302)
        self.assertIsNone(cache.get(state_cache_key(stashed_state)))
        self.assertEqual(
            cache.get(state_cache_key(posted_state)), "posted-code-verifier"
        )

    @override_settings(OPENID_CONNECT_VIEWSET_CONFIG=OPENID_CONNECT_VIEWSET_CONFIG)
    def test_attacker_state_does_not_touch_unrelated_cache_entries(self):
        """
        A form_post response carries a caller-chosen ``state``.
        _clear_login_states must only delete keys in the ``oidc:state:``
        namespace, never raw keys that other apps own.
        """
        cache.set("unrelated-app-key", "important-data")
        view = UserModelOpenIDConnectViewset.as_view({"post": "callback"})
        with patch(
            "oidc.viewsets.OpenIDClient.verify_and_decode_id_token",
            return_value={
                "given_name": "att",
                "family_name": "Acker",
                "email": "attacker@example.com",
                "preferred_username": "att_chosen",
            },
        ):
            response = view(
                self.factory.post(
                    "/", data={"id_token": ID_TOKEN, "state": "unrelated-app-key"}
                ),
                auth_server="default",
            )

        self.assertEqual(response.status_code, 302)
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
        The username form re-POSTs with the original ``?code=`` still on
        the URL, because its ``action=""`` keeps the query string. The
        re-submit must not exchange that spent code again, which the IdP
        rejects as invalid_code. It continues from the ID token stashed
        when the form was rendered. The ``from_username_form=1`` marker
        gates this path.
        """
        continuation = stash_login_continuation(
            {
                "email_verified": False,
                "name": "Bob User",
                "preferred_username": "bob@example.com",
                "given_name": "bob",
                "family_name": "User",
                "email": "bob@example.com",
            }
        )
        view = UserModelOpenIDConnectViewset.as_view({"post": "callback"})
        with patch(
            "oidc.viewsets.OpenIDClient.retrieve_tokens_using_auth_code"
        ) as mock_exchange:
            request = self.factory.post(
                "/?code=stale-already-consumed-code&state=stale-state",
                data={
                    LOGIN_CONTINUATION_FIELD: continuation,
                    "username": "bob_chosen",
                    USERNAME_FORM_MARKER_FIELD: USERNAME_FORM_MARKER_VALUE,
                },
            )
            response = view(request, auth_server="default")
            self.assertEqual(response.status_code, 302)
            mock_exchange.assert_not_called()
            self.assertTrue(User.objects.filter(username="bob_chosen").exists())

    @override_settings(
        OPENID_CONNECT_VIEWSET_CONFIG={
            **OPENID_CONNECT_VIEWSET_CONFIG,
            "USE_EMAIL_USERNAME": False,
        }
    )
    def test_username_form_continuation_is_single_use(self):
        """
        The username form carries a single-use continuation, never the
        raw ID token. The re-submit continues from the stashed claims
        without verifying the token again (its nonce is already spent),
        and replaying the same form body is refused.
        """
        view = UserModelOpenIDConnectViewset.as_view({"post": "callback"})
        with patch(
            "oidc.viewsets.OpenIDClient.verify_and_decode_id_token"
        ) as mock_decode:
            mock_decode.return_value = {
                "family_name": "User",
                "given_name": "carol",
                "email": "carol@example.com",
            }
            response = view(
                self.factory.post("/", data={"id_token": ID_TOKEN}),
                auth_server="default",
            )
            self.assertEqual(response.template_name, "oidc/oidc_user_data_entry.html")
            self.assertNotIn("id_token", response.data)
            continuation = response.data[LOGIN_CONTINUATION_FIELD]
            self.assertTrue(continuation)

            resubmit = {
                LOGIN_CONTINUATION_FIELD: continuation,
                "username": "carol_chosen",
                USERNAME_FORM_MARKER_FIELD: USERNAME_FORM_MARKER_VALUE,
            }
            response = view(
                self.factory.post("/", data=resubmit), auth_server="default"
            )
            self.assertEqual(response.status_code, 302)
            self.assertTrue(User.objects.filter(username="carol_chosen").exists())
            mock_decode.assert_called_once_with(ID_TOKEN)

            User.objects.filter(username="carol_chosen").delete()
            response = view(
                self.factory.post("/", data=resubmit), auth_server="default"
            )
            self.assertEqual(response.status_code, 401)
            self.assertEqual(
                response.template_name, "oidc/oidc_unrecoverable_error.html"
            )
            self.assertFalse(User.objects.filter(username="carol_chosen").exists())

    @override_settings(
        OPENID_CONNECT_VIEWSET_CONFIG={
            **OPENID_CONNECT_VIEWSET_CONFIG,
            "USE_EMAIL_USERNAME": False,
        }
    )
    def test_username_form_resubmit_reuses_userinfo_claims(self):
        """
        An IdP that gives the email only through userinfo can finish the
        username form. The re-submit has no access token, so it reuses the
        claims fetched with the first request's access token.
        """
        view = UserModelOpenIDConnectViewset.as_view({"post": "callback"})
        with (
            patch(
                "oidc.viewsets.OpenIDClient.retrieve_tokens_using_auth_code",
                return_value={"id_token": ID_TOKEN, "access_token": "at"},
            ),
            patch(
                "oidc.viewsets.OpenIDClient.verify_and_decode_id_token",
                return_value={"given_name": "dave", "family_name": "User"},
            ),
            patch(
                "oidc.viewsets.OpenIDClient.validate_access_token",
                side_effect=lambda _decoded, _id_token, access_token: (
                    access_token == "at"
                ),
            ),
            patch(
                "oidc.viewsets.OpenIDClient.retrieve_user_info",
                return_value={
                    "email": "dave@example.com",
                    "given_name": "dave",
                    "family_name": "User",
                },
            ) as mock_userinfo,
        ):
            response = view(
                self.factory.post("/", data={"code": "SplxlOBeZQQYbYS6WxSbIA"}),
                auth_server="default",
            )
            self.assertEqual(response.template_name, "oidc/oidc_user_data_entry.html")
            mock_userinfo.assert_called_once_with("at")

            response = view(
                self.factory.post(
                    "/",
                    data={
                        LOGIN_CONTINUATION_FIELD: response.data[
                            LOGIN_CONTINUATION_FIELD
                        ],
                        "username": "dave_chosen",
                        USERNAME_FORM_MARKER_FIELD: USERNAME_FORM_MARKER_VALUE,
                    },
                ),
                auth_server="default",
            )

        self.assertEqual(response.status_code, 302)
        self.assertEqual(
            User.objects.get(username="dave_chosen").email, "dave@example.com"
        )
        mock_userinfo.assert_called_once_with("at")

    @override_settings(
        OPENID_CONNECT_AUTH_SERVERS=OPENID_CONNECT_AUTH_SERVERS,
        OPENID_CONNECT_VIEWSET_CONFIG=OPENID_CONNECT_VIEWSET_CONFIG,
    )
    def test_username_form_continuation_is_bound_to_its_provider(self):
        """A continuation stashed for one provider is refused by another"""
        continuation = stash_login_continuation(
            {
                "given_name": "erin",
                "family_name": "User",
                "email": "erin@example.com",
            },
            auth_server="pkce",
        )
        view = UserModelOpenIDConnectViewset.as_view({"post": "callback"})
        request = self.factory.post(
            "/",
            data={
                LOGIN_CONTINUATION_FIELD: continuation,
                "username": "erin_chosen",
                USERNAME_FORM_MARKER_FIELD: USERNAME_FORM_MARKER_VALUE,
            },
        )
        response = view(request, auth_server="default")
        self.assertEqual(response.status_code, 401)
        self.assertFalse(User.objects.filter(username="erin_chosen").exists())

    @override_settings(
        OPENID_CONNECT_VIEWSET_CONFIG={
            **OPENID_CONNECT_VIEWSET_CONFIG,
            "USE_EMAIL_USERNAME": False,
        }
    )
    def test_username_form_resubmit_keeps_next(self):
        """The post-auth redirect from ``next`` survives the username form."""
        view = UserModelOpenIDConnectViewset.as_view({"post": "callback"})
        with patch(
            "oidc.viewsets.OpenIDClient.verify_and_decode_id_token",
            return_value={
                "given_name": "heidi",
                "family_name": "User",
                "email": "heidi@example.com",
                REDIRECT_AFTER_AUTH: "https://app.example.com/next",
            },
        ):
            response = view(
                self.factory.post("/", data={"id_token": ID_TOKEN}),
                auth_server="default",
            )
            self.assertEqual(response.template_name, "oidc/oidc_user_data_entry.html")

            response = view(
                self.factory.post(
                    "/",
                    data={
                        LOGIN_CONTINUATION_FIELD: response.data[
                            LOGIN_CONTINUATION_FIELD
                        ],
                        "username": "heidi_chosen",
                        USERNAME_FORM_MARKER_FIELD: USERNAME_FORM_MARKER_VALUE,
                    },
                ),
                auth_server="default",
            )

        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.url, "https://app.example.com/next")

    @override_settings(
        OPENID_CONNECT_AUTH_SERVERS={
            **OPENID_CONNECT_AUTH_SERVERS,
            "default": {
                **OPENID_CONNECT_AUTH_SERVERS["default"],
                "RESPONSE_MODE": "query",
            },
        }
    )
    def test_username_form_without_continuation_is_refused(self):
        """
        A username form that posts no continuation, such as a template
        override that still posts id_token, gets the retry error. It neither
        verifies the posted token nor re-exchanges the code on the URL.
        """
        view = UserModelOpenIDConnectViewset.as_view({"post": "callback"})
        with (
            patch(
                "oidc.viewsets.OpenIDClient.verify_and_decode_id_token"
            ) as mock_decode,
            patch(
                "oidc.viewsets.OpenIDClient.retrieve_tokens_using_auth_code"
            ) as mock_exchange,
            self.assertLogs("oidc.viewsets", level="WARNING") as logs,
        ):
            response = view(
                self.factory.post(
                    "/?code=stale-already-consumed-code",
                    data={
                        "id_token": ID_TOKEN,
                        "username": "mallory_chosen",
                        USERNAME_FORM_MARKER_FIELD: USERNAME_FORM_MARKER_VALUE,
                    },
                ),
                auth_server="default",
            )

        self.assertEqual(response.status_code, 401)
        self.assertEqual(response.template_name, "oidc/oidc_unrecoverable_error.html")
        mock_decode.assert_not_called()
        mock_exchange.assert_not_called()
        self.assertIn(LOGIN_CONTINUATION_FIELD, logs.output[0])
        self.assertFalse(User.objects.filter(username="mallory_chosen").exists())

    @override_settings(
        OPENID_CONNECT_VIEWSET_CONFIG={
            **OPENID_CONNECT_VIEWSET_CONFIG,
            "USE_EMAIL_USERNAME": False,
        }
    )
    def test_failed_userinfo_does_not_render_username_form(self):
        """
        A userinfo response that is not JSON, or not a JSON object, gets the
        retry error. A username form could never finish: its re-submit has no
        access token to fetch the claims again.
        """
        view = UserModelOpenIDConnectViewset.as_view({"post": "callback"})
        for userinfo in (
            {"side_effect": ValueError("Expecting value: line 1 column 1")},
            {"return_value": "abc"},
            {"return_value": None},
        ):
            with (
                self.subTest(**{k: repr(v) for k, v in userinfo.items()}),
                patch(
                    "oidc.viewsets.OpenIDClient.retrieve_tokens_using_auth_code",
                    return_value={"id_token": ID_TOKEN, "access_token": "at"},
                ),
                patch(
                    "oidc.viewsets.OpenIDClient.verify_and_decode_id_token",
                    return_value={"given_name": "erin", "family_name": "User"},
                ),
                patch(
                    "oidc.viewsets.OpenIDClient.validate_access_token",
                    return_value=True,
                ),
                patch(
                    "oidc.viewsets.OpenIDClient.retrieve_user_info", **userinfo
                ) as mock_userinfo,
            ):
                response = view(
                    self.factory.post("/", data={"code": "SplxlOBeZQQYbYS6WxSbIA"}),
                    auth_server="default",
                )

                mock_userinfo.assert_called_once_with("at")
                self.assertEqual(response.status_code, 401)
                self.assertEqual(
                    response.template_name, "oidc/oidc_unrecoverable_error.html"
                )
                self.assertNotIn(LOGIN_CONTINUATION_FIELD, response.data)

    @override_settings(
        OPENID_CONNECT_VIEWSET_CONFIG={
            **OPENID_CONNECT_VIEWSET_CONFIG,
            "USE_EMAIL_USERNAME": False,
        }
    )
    def test_username_form_rerenders_issue_fresh_continuations(self):
        """
        An invalid username and a taken username each re-render the
        form with a new continuation, and the last one completes login.
        """
        User.objects.create(username="taken_name", email="other@example.com")
        continuation = stash_login_continuation(
            {
                "given_name": "heidi",
                "family_name": "User",
                "email": "heidi@example.com",
            }
        )
        view = UserModelOpenIDConnectViewset.as_view({"post": "callback"})

        def submit(key, username):
            return view(
                self.factory.post(
                    "/",
                    data={
                        LOGIN_CONTINUATION_FIELD: key,
                        "username": username,
                        USERNAME_FORM_MARKER_FIELD: USERNAME_FORM_MARKER_VALUE,
                    },
                ),
                auth_server="default",
            )

        seen = {continuation}
        for username, status_code in (("ab", 400), ("taken_name", 200)):
            response = submit(continuation, username)
            self.assertEqual(response.status_code, status_code)
            self.assertEqual(response.template_name, "oidc/oidc_user_data_entry.html")
            self.assertNotIn("id_token", response.data)
            continuation = response.data[LOGIN_CONTINUATION_FIELD]
            self.assertNotIn(continuation, seen)
            seen.add(continuation)

        response = submit(continuation, "heidi_chosen")
        self.assertEqual(response.status_code, 302)
        self.assertTrue(User.objects.filter(username="heidi_chosen").exists())

    @override_settings(OPENID_CONNECT_VIEWSET_CONFIG=OPENID_CONNECT_VIEWSET_CONFIG)
    def test_username_form_continuation_does_not_outlive_id_token(self):
        """
        A continuation lasts as long as its ID token would still verify,
        including the clock-skew leeway.
        """
        view = UserModelOpenIDConnectViewset.as_view({"post": "callback"})
        for name, exp, status_code in (
            ("ivan", time.time() - ID_TOKEN_LEEWAY_SECONDS - 10, 401),
            ("ines", str(int(time.time() - ID_TOKEN_LEEWAY_SECONDS - 10)), 401),
            ("iris", time.time() - 10, 302),
            ("ivy", time.time() + 60, 302),
        ):
            continuation = stash_login_continuation(
                {
                    "given_name": name,
                    "family_name": "User",
                    "email": f"{name}@example.com",
                    "exp": exp,
                }
            )
            request = self.factory.post(
                "/",
                data={
                    LOGIN_CONTINUATION_FIELD: continuation,
                    "username": f"{name}_chosen",
                    USERNAME_FORM_MARKER_FIELD: USERNAME_FORM_MARKER_VALUE,
                },
            )
            response = view(request, auth_server="default")
            self.assertEqual(response.status_code, status_code)
            self.assertEqual(
                User.objects.filter(username=f"{name}_chosen").exists(),
                status_code == 302,
            )

    @override_settings(OPENID_CONNECT_VIEWSET_CONFIG=OPENID_CONNECT_VIEWSET_CONFIG)
    def test_malformed_continuation_is_refused_without_cache_lookup(self):
        """
        A malformed or non-string continuation key gets a 401 without a cache
        read. Some cache backends raise on keys with spaces or over 250
        characters.
        """
        view = UserModelOpenIDConnectViewset.as_view({"post": "callback"})
        for key in ("has spaces", "x" * 300, 7):
            with patch.object(cache, "get") as mock_get:
                request = self.factory.post(
                    "/",
                    data={
                        LOGIN_CONTINUATION_FIELD: key,
                        "username": "judy_chosen",
                        USERNAME_FORM_MARKER_FIELD: USERNAME_FORM_MARKER_VALUE,
                    },
                    format="json",
                )
                response = view(request, auth_server="default")
            self.assertEqual(response.status_code, 401)
            mock_get.assert_not_called()

    @override_settings(OPENID_CONNECT_VIEWSET_CONFIG=OPENID_CONNECT_VIEWSET_CONFIG)
    def test_continuation_consumed_by_concurrent_request_is_refused(self):
        """Only the request whose delete removes the continuation uses it"""
        continuation = stash_login_continuation(
            {
                "given_name": "kim",
                "family_name": "User",
                "email": "kim@example.com",
            }
        )
        view = UserModelOpenIDConnectViewset.as_view({"post": "callback"})
        request = self.factory.post(
            "/",
            data={
                LOGIN_CONTINUATION_FIELD: continuation,
                "username": "kim_chosen",
                USERNAME_FORM_MARKER_FIELD: USERNAME_FORM_MARKER_VALUE,
            },
        )
        with patch.object(cache, "delete", return_value=False):
            response = view(request, auth_server="default")
        self.assertEqual(response.status_code, 401)
        self.assertFalse(User.objects.filter(username="kim_chosen").exists())

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
                LOGIN_CONTINUATION_FIELD: "continuation-key",
                "username_pattern": "^test$",
                "username_help_text": "test help",
            },
        )
        self.assertIn(
            f'name="{LOGIN_CONTINUATION_FIELD}" value="continuation-key"', rendered
        )
        self.assertNotIn('name="id_token"', rendered)
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

    def _assert_unrecoverable_auth_401(self, response):
        """Assert the generic 401 page that asks the user to sign in again."""
        self.assertEqual(response.status_code, 401)
        self.assertEqual(response.template_name, "oidc/oidc_unrecoverable_error.html")
        self.assertEqual(
            response.data.get("error"),
            "Unable to validate authentication request; "
            "Kindly retry authentication process.",
        )
        self.assertEqual(
            response.data.get("error_title"),
            "Authentication request verification failed",
        )

    def test_unrecoverable_error_on_access_token_verification_failed(self):
        """A failed access-token check is logged and shows the generic 401 page."""
        reason = "Failed to validate access token: test reason"
        view = UserModelOpenIDConnectViewset.as_view({"post": "callback"})
        with (
            patch(
                "oidc.viewsets.OpenIDClient.verify_and_decode_id_token",
                return_value={"sub": "user-1"},
            ),
            patch(
                "oidc.viewsets.OpenIDClient.tokens_to_user_info",
                side_effect=TokenVerificationFailed(reason),
            ),
            self.assertLogs("oidc.viewsets", level="WARNING") as logs,
        ):
            request = self.factory.post("/", data={"id_token": "hdr.payload.sig"})
            response = view(request, auth_server="default")

        self._assert_unrecoverable_auth_401(response)
        self.assertNotIn(reason, str(response.data))
        self.assertIn(reason, logs.output[0])

    def test_unrecoverable_error_on_non_ascii_access_token(self):
        """A non-ASCII access token gets the 401 page. The log names the
        reason, and neither the log nor the response holds the token."""
        view = UserModelOpenIDConnectViewset.as_view({"post": "callback"})
        with (
            patch(
                "oidc.viewsets.OpenIDClient.retrieve_tokens_using_auth_code",
                return_value={
                    "id_token": "hdr.payload.sig",
                    "access_token": "t\u00f6ken",
                },
            ),
            patch(
                "oidc.viewsets.OpenIDClient.verify_and_decode_id_token",
                return_value={"sub": "user-1", "at_hash": "abc"},
            ),
            patch.object(
                jwt, "get_unverified_header", return_value={"alg": "RS256"}
            ) as mock_header,
            self.assertLogs("oidc.viewsets", level="WARNING") as logs,
        ):
            request = self.factory.post("/", data={"code": "SplxlOBeZQQYbYS6WxSbIA"})
            response = view(request, auth_server="default")

        mock_header.assert_called_once_with("hdr.payload.sig")
        self._assert_unrecoverable_auth_401(response)
        self.assertIn("cannot compute at_hash", logs.output[0])
        self.assertNotIn("t\u00f6ken", "\n".join(logs.output))
        self.assertNotIn("t\u00f6ken", str(response.data))

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

    def test_created_user_has_unusable_password(self):
        view = UserModelOpenIDConnectViewset.as_view({"post": "callback"})
        with patch(
            "oidc.viewsets.OpenIDClient.verify_and_decode_id_token"
        ) as mock_func:
            mock_func.return_value = {
                "given_name": "sso",
                "family_name": "only",
                "email": "sso@only.com",
                "preferred_username": "ssoonly",
            }
            self.assertFalse(User.objects.filter(username="ssoonly").exists())
            request = self.factory.post("/", data={"id_token": "a.b.c"})
            response = view(request, auth_server="default")

        self.assertEqual(response.status_code, 302)
        user = User.objects.get(username="ssoonly")
        self.assertFalse(user.has_usable_password())

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
    @patch("oidc.viewsets.OpenIDClient.retrieve_tokens_using_auth_code")
    def test_auth_code_flow_token_failure_hides_exception_detail(
        self, mock_retrieve_tokens_using_auth_code
    ):
        """A failed code exchange shows a fixed message, never the exception text"""
        secret = "s3cr3t-value"
        mock_retrieve_tokens_using_auth_code.side_effect = TokenVerificationFailed(
            f"https://example.com/oauth2/v2.0/token?client_secret={secret}"
        )
        view = UserModelOpenIDConnectViewset.as_view({"post": "callback"})
        request = self.factory.post("/", data={"code": "SplxlOBeZQQYbYS6WxSbIA"})
        response = view(request, auth_server="default")

        mock_retrieve_tokens_using_auth_code.assert_called_once()
        self.assertEqual(response.status_code, 401)
        self.assertEqual(response.template_name, "oidc/oidc_unrecoverable_error.html")
        self.assertEqual(
            response.data["error"],
            "Unable to retrieve ID Token. Kindly retry authentication process.",
        )
        self.assertNotIn(secret, str(response.data))

    @override_settings(OPENID_CONNECT_AUTH_SERVERS=OPENID_CONNECT_AUTH_SERVERS)
    def test_callback_post_parameters_hidden_from_error_reports(self):
        """Django error reports mask every POSTed value, credentials included"""
        view = UserModelOpenIDConnectViewset.as_view({"post": "callback"})
        data = {
            "code": "c0de-value",
            "id_token": "t0ken-value",
            "access_token": "acc3ss-value",
            "state": "st4te",
        }
        request = self.factory.post("/", data=data)

        response = view(request, auth_server="default")

        # A malformed id_token fails before any request to the provider's JWKS.
        self.assertEqual(response.status_code, 401)
        reporter_filter = SafeExceptionReporterFilter()
        reported = reporter_filter.get_post_parameters(request)
        self.assertEqual(request.POST["code"], "c0de-value")
        for name in data:
            self.assertEqual(reported[name], reporter_filter.cleansed_substitute)

    @override_settings(
        OPENID_CONNECT_AUTH_SERVERS={
            "default": {
                **OPENID_CONNECT_AUTH_SERVERS["default"],
                "CLIENT_SECRET": "s3cr3t-login-value",
                "REQUEST_MODE": "form-post",
            }
        }
    )
    def test_client_setup_locals_hidden_from_error_reports(self):
        """A misconfigured client fails login without its secret in error reports"""
        secret = "s3cr3t-login-value"
        view = UserModelOpenIDConnectViewset.as_view({"get": "login"})

        frames = escaped_frames(
            lambda: view(self.factory.get("/"), auth_server="default"),
            ImproperlyConfigured,
            "_get_client",
        )

        self.assertIn(secret, str(frames[0].f_locals["auth_config"]))
        self.assertIn("auth_config", reported_locals(frames[0]))
        for frame in frames:
            self.assertNotIn(secret, str(reported_locals(frame)))

    @override_settings(
        OPENID_CONNECT_VIEWSET_CONFIG={
            **OPENID_CONNECT_VIEWSET_CONFIG,
            "JWT_SECRET_KEY": "s3cr3t-jwt-value",
            "SSO_COOKIE_SAMESITE": "None",
            "SSO_COOKIE_SECURE": False,
        }
    )
    def test_viewset_setup_locals_hidden_from_error_reports(self):
        """A misconfigured viewset fails without its JWT secret in error reports"""
        secret = "s3cr3t-jwt-value"

        frames = escaped_frames(
            UserModelOpenIDConnectViewset, ImproperlyConfigured, "__init__"
        )

        self.assertEqual(frames[0].f_locals["config"]["JWT_SECRET_KEY"], secret)
        self.assertIn("config", reported_locals(frames[0]))
        for frame in frames:
            self.assertNotIn(secret, str(reported_locals(frame)))

    @override_settings(OPENID_CONNECT_AUTH_SERVERS=OPENID_CONNECT_AUTH_SERVERS)
    @patch("oidc.viewsets.OpenIDClient.verify_and_decode_id_token")
    @patch("oidc.viewsets.OpenIDClient.retrieve_tokens_using_auth_code")
    def test_callback_locals_hidden_from_error_reports(
        self, mock_retrieve_tokens_using_auth_code, mock_verify
    ):
        """An error the callback doesn't catch shows no tokens in error reports"""
        tokens = {
            "access_token": "acc3ss-value",
            "refresh_token": "r3fresh-value",
            "id_token": "id-t0ken-value",
        }
        mock_retrieve_tokens_using_auth_code.return_value = tokens
        mock_verify.side_effect = RuntimeError("unexpected")
        view = UserModelOpenIDConnectViewset.as_view({"post": "callback"})
        request = self.factory.post("/", data={"code": "c0de-value"})

        frames = escaped_frames(
            lambda: view(request, auth_server="default"), RuntimeError, "callback"
        )

        self.assertIn(tokens["access_token"], str(frames[0].f_locals["user_tokens"]))
        self.assertIn("user_tokens", reported_locals(frames[0]))
        for frame in frames:
            for value in tokens.values():
                self.assertNotIn(value, str(reported_locals(frame)))

    @override_settings(OPENID_CONNECT_AUTH_SERVERS=OPENID_CONNECT_AUTH_SERVERS)
    @override_settings(OPENID_CONNECT_VIEWSET_CONFIG=OPENID_CONNECT_VIEWSET_CONFIG)
    @patch("oidc.viewsets.OpenIDClient.verify_and_decode_id_token")
    def test_invalid_id_token_renders_error_page_not_500(self, mock_verify):
        """Any token-validation failure shows the error page, logged, not a crash."""
        failures = {
            "expired": jwt.exceptions.ExpiredSignatureError("expired"),
            "missing claim": jwt.exceptions.MissingRequiredClaimError("exp"),
            "wrong issuer": jwt.exceptions.InvalidIssuerError("bad iss"),
            "disallowed algorithm": jwt.exceptions.InvalidAlgorithmError("alg"),
        }
        view = UserModelOpenIDConnectViewset.as_view({"post": "callback"})
        for name, failure in failures.items():
            with self.subTest(name):
                mock_verify.side_effect = failure
                request = self.factory.post("/", data={"id_token": "stale"})
                with self.assertLogs("oidc.viewsets", level="WARNING"):
                    response = view(request, auth_server="default")
                self.assertEqual(response.status_code, 401)
                self.assertEqual(
                    response.template_name, "oidc/oidc_unrecoverable_error.html"
                )

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
    @patch("oidc.viewsets.OpenIDClient.logout")
    def test_logout_locals_hidden_from_error_reports(self, mock_client_logout):
        """An error during logout shows no stashed id_token in error reports"""
        id_token = "ey.st4shed.jwt"
        mock_client_logout.side_effect = RuntimeError("unexpected")
        view = BaseOpenIDConnectViewset.as_view({"get": "logout"})
        request = self.factory.get("/")
        request.session = {"oidc_id_token": id_token}

        frames = escaped_frames(
            lambda: view(request, auth_server="default"), RuntimeError, "logout"
        )

        self.assertEqual(frames[0].f_locals["id_token_hint"], id_token)
        self.assertIn("id_token_hint", reported_locals(frames[0]))
        for frame in frames:
            self.assertNotIn(id_token, str(reported_locals(frame)))

    @override_settings(OPENID_CONNECT_VIEWSET_CONFIG=OPENID_CONNECT_VIEWSET_CONFIG)
    def test_username_form_render_hides_continuation_from_error_reports(self):
        """
        A username form that fails to render, after the view has returned,
        shows no login continuation key in error reports
        """
        continuation = "c0ntinuation-key"
        viewset = UserModelOpenIDConnectViewset()
        response = viewset._username_form_response(
            {LOGIN_CONTINUATION_FIELD: continuation}
        )
        response.accepted_renderer = next(
            renderer()
            for renderer in viewset.renderer_classes
            if renderer.format == "html"
        )
        response.accepted_media_type = "text/html"
        response.renderer_context = {
            "request": self.factory.get("/"),
            "response": response,
            "view": viewset,
        }
        # The form extends base.html, which only the host project supplies.
        engine = settings.TEMPLATES[0]
        without_base = {
            **engine,
            "DIRS": [d for d in engine["DIRS"] if not d.endswith("tests/templates")],
        }

        with override_settings(TEMPLATES=[without_base]):
            frames = escaped_frames(
                response.render, TemplateDoesNotExist, "rendered_content"
            )

        self.assertTrue(any(continuation in str(f.f_locals) for f in frames))
        for frame in frames:
            self.assertNotIn(continuation, str(reported_locals(frame)))

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

    def test_user_defaults_not_shared_between_users(self):
        ona_defaults = {"is_active": True}
        config = {
            **copy.deepcopy(OPENID_CONNECT_VIEWSET_CONFIG),
            "USER_DEFAULTS": {"^.*@ona.io$": ona_defaults},
        }
        view = UserModelOpenIDConnectViewset.as_view({"post": "callback"})
        data = {"id_token": "a.b.c"}
        with (
            override_settings(OPENID_CONNECT_VIEWSET_CONFIG=config),
            patch("oidc.viewsets.OpenIDClient.verify_and_decode_id_token") as mock_func,
        ):
            mock_func.return_value = {
                "given_name": "anna",
                "family_name": "first",
                "sub": "anna@ona.io",
            }
            response = view(self.factory.post("/", data=data), auth_server="default")
            self.assertEqual(response.status_code, 302)
            self.assertEqual(User.objects.get(username="anna").last_name, "first")

            mock_func.return_value = {"given_name": "ben", "sub": "ben@ona.io"}
            response = view(self.factory.post("/", data=data), auth_server="default")
            self.assertEqual(response.status_code, 302)

        self.assertEqual(User.objects.get(username="ben").last_name, "")
        self.assertEqual(ona_defaults, {"is_active": True})

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

    def test_nonce_and_key_failures_show_a_fixed_message(self):
        """A nonce or signing-key failure shows a fixed message and logs the
        reason."""
        view = UserModelOpenIDConnectViewset.as_view({"post": "callback"})
        for error in (
            NonceVerificationFailed("Failed to verify returned nonce value"),
            NoJSONWebKeyFound("Failed to retrieve key ID described in Token"),
        ):
            with (
                self.subTest(error=type(error).__name__),
                patch(
                    "oidc.viewsets.OpenIDClient.verify_and_decode_id_token",
                    side_effect=error,
                ),
                self.assertLogs("oidc.viewsets", level="WARNING") as logs,
            ):
                response = view(
                    self.factory.post("/", data={"id_token": ID_TOKEN}),
                    auth_server="default",
                )

                self.assertEqual(response.status_code, 401)
                self.assertEqual(
                    response.data["error"],
                    "Unable to validate authentication request; "
                    "Kindly retry authentication process.",
                )
                self.assertNotIn(str(error), str(response.data))
                self.assertIn(str(error), logs.output[0])

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
                "ENFORCE_BROWSER_BINDING": False,
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
                "ENFORCE_BROWSER_BINDING": False,
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
                "ENFORCE_BROWSER_BINDING": False,
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
                "ENFORCE_BROWSER_BINDING": False,
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
                "ENFORCE_BROWSER_BINDING": False,
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
        # Tokens must carry exp to be accepted at all; exp-less tokens
        # have their own rejection test in tests.test_utils.
        claims.setdefault("exp", timezone.now() + timedelta(minutes=5))
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
        self.assertEqual(payload["username"], "jdoe")

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


class TestSSOCookieJWTExpiry(TestCase):
    """The SSO cookie's JWT must be a bounded credential, not a forever token."""

    def setUp(self):
        self.factory = APIRequestFactory()
        self.user = User.objects.create(
            username="jdoe", email="jdoe@example.com", is_active=True
        )

    def _minted_payload(self):
        request = self.factory.get("/")
        response = BaseOpenIDConnectViewset().generate_successful_response(
            request, self.user
        )
        return jwt.decode(
            response.cookies.get("SSO").value, "abc", algorithms=["HS256"]
        )

    @override_settings(
        OPENID_CONNECT_VIEWSET_CONFIG={
            **OPENID_CONNECT_VIEWSET_CONFIG,
            "REDIRECT_AFTER_AUTH": "http://localhost:3000",
        }
    )
    def test_minted_sso_jwt_expires_after_cookie_max_age(self):
        """The minted JWT carries iat/exp, expiring SSO_COOKIE_MAX_AGE later."""
        payload = self._minted_payload()
        self.assertEqual(payload["email"], "jdoe@example.com")
        # OPENID_CONNECT_VIEWSET_CONFIG sets SSO_COOKIE_MAX_AGE to 30 days.
        self.assertEqual(payload["exp"] - payload["iat"], 60 * 60 * 24 * 30)

    @override_settings(
        OPENID_CONNECT_VIEWSET_CONFIG={
            **{
                k: v
                for k, v in OPENID_CONNECT_VIEWSET_CONFIG.items()
                if k != "SSO_COOKIE_MAX_AGE"
            },
            "REDIRECT_AFTER_AUTH": "http://localhost:3000",
        }
    )
    def test_minted_sso_jwt_gets_default_expiry_without_cookie_max_age(self):
        """A session cookie (no max age) still carries a bounded JWT: 7 days."""
        payload = self._minted_payload()
        self.assertEqual(payload["exp"] - payload["iat"], 60 * 60 * 24 * 7)

    @override_settings(
        OPENID_CONNECT_VIEWSET_CONFIG={
            "REDIRECT_AFTER_AUTH": "http://localhost:3000",
        }
    )
    def test_minting_without_jwt_secret_raises_improperly_configured(self):
        """USE_SSO_COOKIE without JWT_SECRET_KEY is a config error, not a crash."""
        request = self.factory.get("/")
        with self.assertRaises(ImproperlyConfigured):
            BaseOpenIDConnectViewset().generate_successful_response(
                request, self.user
            )

    @override_settings(
        OPENID_CONNECT_VIEWSET_CONFIG={
            "JWT_SECRET_KEY": "abc",
            "REDIRECT_AFTER_AUTH": "http://localhost:3000",
        }
    )
    def test_minting_defaults_to_hs256_when_algorithm_unset(self):
        """A config with a secret but no JWT_ALGORITHM mints with HS256."""
        payload = self._minted_payload()
        self.assertEqual(payload["email"], "jdoe@example.com")

    @override_settings(
        OPENID_CONNECT_VIEWSET_CONFIG={
            "USE_AUTH_BACKEND": True,
            "REDIRECT_AFTER_AUTH": "http://localhost:3000",
        }
    )
    def test_missing_jwt_secret_is_rejected_before_login(self):
        """The config error must fire before a session is established.

        The factory request has no session, so login() would raise an
        unrelated error if it ran first; seeing ImproperlyConfigured
        proves the config check comes before login().
        """
        request = self.factory.get("/")
        with self.assertRaises(ImproperlyConfigured):
            BaseOpenIDConnectViewset().generate_successful_response(
                request, self.user
            )

    @override_settings(
        OPENID_CONNECT_VIEWSET_CONFIG={
            **OPENID_CONNECT_VIEWSET_CONFIG,
            "SSO_COOKIE_MAX_AGE": 0,
            "REDIRECT_AFTER_AUTH": "http://localhost:3000",
        }
    )
    def test_explicit_zero_cookie_max_age_is_honoured(self):
        """SSO_COOKIE_MAX_AGE=0 mints an already-expired JWT, not a 7-day one."""
        request = self.factory.get("/")
        response = BaseOpenIDConnectViewset().generate_successful_response(
            request, self.user
        )
        payload = jwt.decode(
            response.cookies.get("SSO").value,
            "abc",
            algorithms=["HS256"],
            options={"verify_exp": False},
        )
        self.assertEqual(payload["exp"] - payload["iat"], 0)

    @override_settings(
        USE_TZ=False,
        TIME_ZONE="Africa/Nairobi",
        OPENID_CONNECT_VIEWSET_CONFIG={
            **OPENID_CONNECT_VIEWSET_CONFIG,
            "REDIRECT_AFTER_AUTH": "http://localhost:3000",
        },
    )
    def test_minted_jwt_authenticates_under_use_tz_false_ahead_of_utc(self):
        """A JWT minted with USE_TZ=False in a UTC+3 timezone authenticates.

        JWT timestamps are UTC by definition. A local-time iat from a
        UTC+3 clock sits three hours in the future, so PyJWT rejects the
        freshly minted token as immature and SSO authentication breaks.

        Django pins the process timezone to settings.TIME_ZONE when
        settings first load, which override_settings does not redo, so
        the naive clock is moved to Nairobi for the duration by hand.
        """
        original_tz = os.environ.get("TZ")
        os.environ["TZ"] = "Africa/Nairobi"
        time.tzset()
        try:
            request = self.factory.get("/")
            response = BaseOpenIDConnectViewset().generate_successful_response(
                request, self.user
            )
            session_request = self.factory.get("/oidc/default/session")
            session_request.COOKIES["SSO"] = response.cookies.get("SSO").value
            session_response = BaseOpenIDConnectViewset.as_view(
                {"get": "session"}
            )(session_request, auth_server="default")
            self.assertEqual(session_response.status_code, 200)
            self.assertEqual(session_response.data, {"username": "jdoe"})
        finally:
            if original_tz is None:
                del os.environ["TZ"]
            else:
                os.environ["TZ"] = original_tz
            time.tzset()


# The browser-visible name prefix of the binding slot cookies.
# Deliberately a literal, not an import, so renaming the cookies the
# deployed browsers already hold fails a test.
BINDING_COOKIE_PREFIX = "oidc_login_bind"

# Built without ENFORCE_BROWSER_BINDING so these tests exercise the
# default, which is enforcement ON.
BINDING_AUTH_SERVERS = {
    "default": {
        k: v
        for k, v in OPENID_CONNECT_AUTH_SERVERS["default"].items()
        if k != "ENFORCE_BROWSER_BINDING"
    }
}


@override_settings(
    OPENID_CONNECT_AUTH_SERVERS=BINDING_AUTH_SERVERS,
    OPENID_CONNECT_VIEWSET_CONFIG=OPENID_CONNECT_VIEWSET_CONFIG,
)
class LoginBrowserBindingTestCase(TestCase):
    """Authorization responses must come back to the browser that
    started the login (login CSRF defense, RFC 9700 4.4)."""

    def setUp(self):
        self.factory = APIRequestFactory()
        cache.clear()

    def test_callback_without_binding_cookie_is_rejected(self):
        """A callback in a browser that never started a login is rejected.

        The response's state must match the signed cookie login() set,
        before any cache entry is consulted or any token is verified.
        """
        view = UserModelOpenIDConnectViewset.as_view({"post": "callback"})
        with patch(
            "oidc.viewsets.OpenIDClient.verify_and_decode_id_token"
        ) as mock_verify:
            request = self.factory.post(
                "/", data={"id_token": "a.b.c", "state": "attacker-state"}
            )
            response = view(request, auth_server="default")
        self.assertEqual(response.status_code, 401)
        mock_verify.assert_not_called()

    def test_login_sets_binding_cookie_that_its_callback_satisfies(self):
        """The login redirect sets a cookie its own callback accepts.

        The state in the login redirect URL plus the cookie login() set
        are exactly what the callback requires, end to end.
        """
        jar = {}
        state, login_response = self._start_login_response(jar)
        self.assertEqual(login_response.status_code, 302)

        binding_cookies = self._binding_cookies(login_response)
        self.assertEqual(len(binding_cookies), 1)
        self.assertTrue(next(iter(binding_cookies.values()))["httponly"])
        self._store_cookies(jar, login_response)

        view = UserModelOpenIDConnectViewset.as_view({"post": "callback"})
        with patch(
            "oidc.viewsets.OpenIDClient.verify_and_decode_id_token"
        ) as mock_verify:
            mock_verify.return_value = {
                "given_name": "anna",
                "family_name": "doe",
                "email": "anna@example.com",
                "preferred_username": "anna",
            }
            request = self.factory.post(
                "/", data={"id_token": "a.b.c", "state": state}
            )
            request.COOKIES.update(self._cross_site_post_cookies(jar))
            response = view(request, auth_server="default")
        self.assertEqual(response.status_code, 302)
        mock_verify.assert_called_once()

    @staticmethod
    def _binding_cookies(response):
        """The binding cookie morsels a response sets, by cookie name."""
        return {
            name: morsel
            for name, morsel in response.cookies.items()
            if name.startswith(BINDING_COOKIE_PREFIX) and morsel["max-age"] != 0
        }

    @staticmethod
    def _store_cookies(jar, response):
        """Apply a response's Set-Cookie headers to a simulated browser jar."""
        for name, morsel in response.cookies.items():
            if morsel["max-age"] == 0:
                # delete_cookie sends Max-Age=0; a browser drops the cookie.
                jar.pop(name, None)
            else:
                jar[name] = morsel

    @staticmethod
    def _cross_site_post_cookies(jar):
        """The subset of ``jar`` a browser sends on a cross-site POST.

        Browsers withhold SameSite=Lax (and Strict) cookies from
        cross-site POSTs, which is how a form_post IdP delivers the
        authorization response.
        """
        return {
            name: morsel.value
            for name, morsel in jar.items()
            if morsel["samesite"] == "None"
        }

    def _callback_with_cookies(self, state, cookies, auth_server="default"):
        view = UserModelOpenIDConnectViewset.as_view({"post": "callback"})
        with patch(
            "oidc.viewsets.OpenIDClient.verify_and_decode_id_token"
        ) as mock_verify:
            mock_verify.return_value = {
                "given_name": "anna",
                "family_name": "doe",
                "email": "anna@example.com",
                "preferred_username": "anna",
            }
            request = self.factory.post(
                "/", data={"id_token": "a.b.c", "state": state}
            )
            request.COOKIES.update(cookies)
            return view(request, auth_server=auth_server)

    def _start_login_response(self, jar, auth_server="default"):
        """GET the login action sending ``jar``'s cookies; return (state, response)."""
        login_view = UserModelOpenIDConnectViewset.as_view({"get": "login"})
        request = self.factory.get("/")
        request.COOKIES.update(
            {name: morsel.value for name, morsel in jar.items()}
        )
        response = login_view(request, auth_server=auth_server)
        state = parse_qs(urlparse(response.url).query)["state"][0]
        return state, response

    def test_overlapping_login_starts_can_both_complete(self):
        """Two logins started before either response lands can both finish.

        Both requests go out with the same initial cookie jar, so
        neither start sees the other's Set-Cookie, and the browser
        then stores both responses' cookies. Neither callback may be
        rejected.
        """
        jar = {}
        first_state, first_response = self._start_login_response(jar)
        second_state, second_response = self._start_login_response(jar)
        self._store_cookies(jar, first_response)
        self._store_cookies(jar, second_response)
        for state in (first_state, second_state):
            with self.subTest(state=state):
                response = self._callback_with_cookies(
                    state, self._cross_site_post_cookies(jar)
                )
                self.assertEqual(response.status_code, 302)

    def test_query_login_start_keeps_form_post_login_completable(self):
        """A query-mode login start does not break a form_post login in flight.

        The form_post provider's callback is a cross-site POST, which
        the browser only sends SameSite=None cookies on. A later login
        start against a query-mode provider must not leave the first
        login's binding in a cookie the browser withholds from that POST.
        """
        with override_settings(
            OPENID_CONNECT_AUTH_SERVERS={
                **BINDING_AUTH_SERVERS,
                "queryidp": {
                    **BINDING_AUTH_SERVERS["default"],
                    "RESPONSE_MODE": "query",
                },
            }
        ):
            jar = {}
            form_post_state, response = self._start_login_response(jar)
            self._store_cookies(jar, response)
            _, response = self._start_login_response(jar, auth_server="queryidp")
            self._store_cookies(jar, response)
            response = self._callback_with_cookies(
                form_post_state, self._cross_site_post_cookies(jar)
            )
            self.assertEqual(response.status_code, 302)

    def test_repeated_login_starts_keep_a_bounded_cookie_jar(self):
        """Abandoned login starts cannot grow the cookie jar without bound.

        Unchecked growth lets a hostile page drive the Cookie header
        past browser and proxy limits, breaking the whole site for the
        victim until the cookies expire.
        """
        jar = {}
        now = time.time()
        for offset in range(48):
            # Distinct clock ticks exercise eviction age-ordering
            # even when the loop runs within one real second.
            with patch("time.time", return_value=now + offset):
                _, response = self._start_login_response(jar)
            self._store_cookies(jar, response)
        binding = [name for name in jar if name.startswith(BINDING_COOKIE_PREFIX)]
        self.assertEqual(len(binding), 6)

    def test_burst_of_racing_login_starts_keeps_the_jar_bounded(self):
        """Starts racing on one cookie jar cannot grow it past the cap.

        Every request goes out before any response lands, so no start
        sees another's Set-Cookie. That is how a hostile page grows
        the jar fastest. The browser must still end up with a bounded
        set of binding cookies and a Cookie header far below proxy
        header limits, with the newest attempt completable and the
        earliest evicted.
        """
        initial_jar = {}
        started = [self._start_login_response(initial_jar) for _ in range(48)]
        jar = {}
        for _, response in started:
            self._store_cookies(jar, response)
        binding = [name for name in jar if name.startswith(BINDING_COOKIE_PREFIX)]
        self.assertEqual(len(binding), 6)
        cookie_header = "; ".join(
            f"{name}={morsel.value}" for name, morsel in jar.items()
        )
        self.assertLess(len(cookie_header), 4096)
        response = self._callback_with_cookies(
            started[-1][0], self._cross_site_post_cookies(jar)
        )
        self.assertEqual(response.status_code, 302)
        response = self._callback_with_cookies(
            started[0][0], self._cross_site_post_cookies(jar)
        )
        self.assertEqual(response.status_code, 401)

    def test_racing_starts_on_a_partly_filled_jar_stay_completable(self):
        """Foreign traffic cannot make racing starts overwrite a binding.

        Browser A holds two pending logins; other browsers' starts
        then advance the shared slot counter; A fires two more starts
        that race on its unchanged jar. All four of A's logins stay
        independently completable, since the browser remains below the
        pending-attempt limit.
        """
        jar = {}
        states = []
        for _ in range(2):
            state, response = self._start_login_response(jar)
            self._store_cookies(jar, response)
            states.append(state)
        for _ in range(4):
            # Other browsers' starts advance the shared counter, but
            # their responses never reach browser A's jar.
            self._start_login_response({})
        racing = [self._start_login_response(jar) for _ in range(2)]
        for state, response in racing:
            states.append(state)
            self._store_cookies(jar, response)
        for state in states:
            with self.subTest(state=state):
                response = self._callback_with_cookies(
                    state, self._cross_site_post_cookies(jar)
                )
                self.assertEqual(response.status_code, 302)

    def test_response_order_races_keep_every_login_completable(self):
        """Responses landing out of order cannot cost a pending login.

        Two logins are pending. A and B start against the same jar; B's
        response reaches the browser while A's is still outstanding,
        and C starts against that updated jar. A's and C's responses
        then land. All five logins must stay completable, since the
        browser never exceeds the pending-attempt limit.
        """
        jar = {}
        states = []
        for _ in range(2):
            state, response = self._start_login_response(jar)
            self._store_cookies(jar, response)
            states.append(state)
        state_a, response_a = self._start_login_response(jar)
        state_b, response_b = self._start_login_response(jar)
        self._store_cookies(jar, response_b)
        state_c, response_c = self._start_login_response(jar)
        self._store_cookies(jar, response_a)
        self._store_cookies(jar, response_c)
        states += [state_a, state_b, state_c]
        for state in states:
            with self.subTest(state=state):
                response = self._callback_with_cookies(
                    state, self._cross_site_post_cookies(jar)
                )
                self.assertEqual(response.status_code, 302)

    def test_cap_evicts_the_oldest_attempt_and_keeps_the_newest(self):
        """Past the cap the oldest attempt is evicted and the newest stay completable."""
        jar = {}
        states = []
        now = time.time()
        for offset in range(7):
            with patch("time.time", return_value=now + offset):
                state, response = self._start_login_response(jar)
            self._store_cookies(jar, response)
            states.append(state)
        response = self._callback_with_cookies(
            states[0], self._cross_site_post_cookies(jar)
        )
        self.assertEqual(response.status_code, 401)
        response = self._callback_with_cookies(
            states[-1], self._cross_site_post_cookies(jar)
        )
        self.assertEqual(response.status_code, 302)

    def test_completed_login_expires_only_its_own_binding_cookie(self):
        """The success response deletes the finished attempt's cookie, no other.

        A still-pending attempt's cookie survives and that login stays
        completable; the browser is left with no cookie for the spent
        state.
        """
        jar = {}
        first_state, response = self._start_login_response(jar)
        self._store_cookies(jar, response)
        second_state, response = self._start_login_response(jar)
        self._store_cookies(jar, response)

        response = self._callback_with_cookies(
            first_state, self._cross_site_post_cookies(jar)
        )
        self.assertEqual(response.status_code, 302)
        self._store_cookies(jar, response)
        remaining = [
            name for name in jar if name.startswith(BINDING_COOKIE_PREFIX)
        ]
        self.assertEqual(len(remaining), 1)

        response = self._callback_with_cookies(
            second_state, self._cross_site_post_cookies(jar)
        )
        self.assertEqual(response.status_code, 302)

    def test_username_form_continuation_stays_bound_and_cleans_up(self):
        """The username-form re-submit passes binding and ends the attempt.

        A callback whose username is already taken renders the form
        without ending the attempt. The same-origin re-POST carries
        the state and the binding cookie and must pass the binding
        check, and the success response deletes the attempt's binding
        cookie.
        """
        User.objects.create(username="anna", email="anna@example.com")
        claims = {
            "given_name": "anna",
            "family_name": "doe",
            "email": "second.anna@example.com",
            "preferred_username": "anna",
        }
        jar = {}
        state, response = self._start_login_response(jar)
        self._store_cookies(jar, response)

        view = UserModelOpenIDConnectViewset.as_view({"post": "callback"})
        with patch(
            "oidc.viewsets.OpenIDClient.verify_and_decode_id_token"
        ) as mock_verify:
            mock_verify.return_value = claims
            request = self.factory.post(
                "/", data={"id_token": "a.b.c", "state": state}
            )
            request.COOKIES.update(self._cross_site_post_cookies(jar))
            response = view(request, auth_server="default")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.template_name, "oidc/oidc_user_data_entry.html")

        with patch(
            "oidc.viewsets.OpenIDClient.verify_and_decode_id_token"
        ) as mock_verify:
            mock_verify.return_value = claims
            request = self.factory.post(
                "/",
                data={
                    "id_token": "a.b.c",
                    "state": state,
                    "username": "annabelle",
                    USERNAME_FORM_MARKER_FIELD: USERNAME_FORM_MARKER_VALUE,
                },
            )
            # The re-POST is same-origin, so the browser sends every
            # cookie in the jar regardless of SameSite.
            request.COOKIES.update(
                {name: morsel.value for name, morsel in jar.items()}
            )
            response = view(request, auth_server="default")
        self.assertEqual(response.status_code, 302)
        self.assertTrue(User.objects.filter(username="annabelle").exists())
        self._store_cookies(jar, response)
        self.assertEqual(
            [name for name in jar if name.startswith(BINDING_COOKIE_PREFIX)], []
        )

    def test_rejected_unknown_user_login_expires_its_binding_cookie(self):
        """The not-authorized response also deletes the attempt's cookie.

        With AUTO_CREATE_USER off and no matching account the flow ends
        at that 401, so the attempt's cookie must not linger.
        """
        with override_settings(
            OPENID_CONNECT_VIEWSET_CONFIG={
                **OPENID_CONNECT_VIEWSET_CONFIG,
                "AUTO_CREATE_USER": False,
            }
        ):
            jar = {}
            state, response = self._start_login_response(jar)
            self._store_cookies(jar, response)
            response = self._callback_with_cookies(
                state, self._cross_site_post_cookies(jar)
            )
            self.assertEqual(response.status_code, 401)
            self._store_cookies(jar, response)
            self.assertEqual(
                [name for name in jar if name.startswith(BINDING_COOKIE_PREFIX)],
                [],
            )

    def test_login_in_second_tab_keeps_first_tab_completable(self):
        """A newer login start does not invalidate an older tab's login."""
        jar = {}
        first_state, response = self._start_login_response(jar)
        self._store_cookies(jar, response)
        _, response = self._start_login_response(jar)
        self._store_cookies(jar, response)
        response = self._callback_with_cookies(
            first_state, self._cross_site_post_cookies(jar)
        )
        self.assertEqual(response.status_code, 302)

    def test_many_sequential_login_starts_keep_the_oldest_completable(self):
        """No number of newer login starts evicts an older attempt's binding."""
        jar = {}
        oldest_state, response = self._start_login_response(jar)
        self._store_cookies(jar, response)
        for _ in range(3):
            _, response = self._start_login_response(jar)
            self._store_cookies(jar, response)
        response = self._callback_with_cookies(
            oldest_state, self._cross_site_post_cookies(jar)
        )
        self.assertEqual(response.status_code, 302)

    def test_attacker_state_with_victim_cookie_is_rejected(self):
        """A response for a login this browser never started is rejected.

        This is the login CSRF attack. The victim's browser holds a
        binding cookie from their own login start, but the delivered
        response carries the attacker's state.
        """
        victim_jar = {}
        _, response = self._start_login_response(victim_jar)
        self._store_cookies(victim_jar, response)
        attacker_state, _ = self._start_login_response({})
        response = self._callback_with_cookies(
            attacker_state, self._cross_site_post_cookies(victim_jar)
        )
        self.assertEqual(response.status_code, 401)

    def test_tampered_binding_cookie_is_rejected(self):
        """A binding cookie that fails signature verification binds nothing."""
        jar = {}
        state, response = self._start_login_response(jar)
        self._store_cookies(jar, response)
        cookies = {
            name: value[:-1]
            for name, value in self._cross_site_post_cookies(jar).items()
        }
        response = self._callback_with_cookies(state, cookies)
        self.assertEqual(response.status_code, 401)

    def test_opted_out_server_keeps_the_old_behaviour(self):
        """With ENFORCE_BROWSER_BINDING=False no cookie is set and none is required."""
        with override_settings(
            OPENID_CONNECT_AUTH_SERVERS={
                "default": {
                    **BINDING_AUTH_SERVERS["default"],
                    "ENFORCE_BROWSER_BINDING": False,
                }
            }
        ):
            _, login_response = self._start_login_response({})
            self.assertEqual(self._binding_cookies(login_response), {})
            response = self._callback_with_cookies("any-state", {})
            self.assertEqual(response.status_code, 302)

    def test_binding_cookie_attributes_follow_the_response_mode(self):
        """form_post needs SameSite=None + Secure; query mode gets Lax.

        The IdP delivers a form_post response as a cross-site POST,
        which browsers strip Lax cookies from, and they only accept
        SameSite=None cookies over HTTPS.
        """
        _, response = self._start_login_response({})
        (cookie,) = self._binding_cookies(response).values()
        self.assertEqual(cookie["samesite"], "None")
        self.assertTrue(cookie["secure"])

        with override_settings(
            OPENID_CONNECT_AUTH_SERVERS={
                "default": {
                    **BINDING_AUTH_SERVERS["default"],
                    "RESPONSE_MODE": "query",
                }
            }
        ):
            _, response = self._start_login_response({})
            (cookie,) = self._binding_cookies(response).values()
            self.assertEqual(cookie["samesite"], "Lax")
