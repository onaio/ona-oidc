"""
Tests for the OpenID Client
"""

import json

from django.contrib.auth import get_user_model
from django.core.cache import cache
from django.test import TestCase
from django.test.utils import override_settings
from django.utils import timezone

from mock import MagicMock, patch
from rest_framework.test import APIRequestFactory

from oidc.client import OpenIDClient
from oidc.viewsets import BaseOpenIDConnectViewset, UserModelOpenIDConnectViewset

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
            self.assertTrue(
                response.rendered_content.startswith(
                    b'{"error":"Username should only contain word characters & numbers and should have 3 or more characters"'
                )
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
    @patch("oidc.viewsets.OpenIDClient.retrieve_token_using_auth_code")
    def test_auth_code_flow(self, mock_retrieve_auth_code):
        """
        Test that the authorization code flow works as expected
        """
        mock_retrieve_auth_code.return_value = "ssad9012.fdfdfdswg4gdfs.sadadsods"
        view = UserModelOpenIDConnectViewset.as_view({"post": "callback"})
        data = {"code": "SplxlOBeZQQYbYS6WxSbIA"}
        user_count = User.objects.filter(username="john").count()
        request = self.factory.post("/", data=data)
        response = view(request, auth_server="default")

        # Assert that the retrieve_token_using_auth_code function was called
        # and the code token was passed
        self.assertTrue(mock_retrieve_auth_code, True)
        self.assertEqual(mock_retrieve_auth_code.call_args[0][0], data["code"])

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
        self.assertEqual(response.headers["Clear-Site-Data"], '"cache", "cookies"')

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
    @patch.object(OpenIDClient, "retrieve_token_using_auth_code")
    @patch.object(OpenIDClient, "verify_and_decode_id_token")
    def test_pkce_flow_mode_form_post(
        self, mock_verify_and_decode_id_token, mock_retrieve_token_using_auth_code
    ):
        """PKCE flow works as expected with form_post response mode"""
        mock_verify_and_decode_id_token.return_value = {
            "given_name": "john",
            "family_name": "doe",
            "email": "john@example.com",
            "preferred_username": "john",
        }
        mock_retrieve_token_using_auth_code.return_value = "id_token"
        view = UserModelOpenIDConnectViewset.as_view({"post": "callback"})
        # Simulate the code verifier being in the cache
        cache.set("pkce_123", "123")

        data = {"state": "pkce_123", "code": "auth_code"}
        request = self.factory.post("/", data=data)
        response = view(request, auth_server="pkce")

        self.assertEqual(response.status_code, 302)

        user = User.objects.get(username="john")
        self.assertEqual(user.email, "john@example.com")
        self.assertEqual(user.first_name, "john")
        self.assertEqual(user.last_name, "doe")
        mock_retrieve_token_using_auth_code.assert_called_once_with(
            "auth_code", code_verifier="123"
        )

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
    @patch.object(OpenIDClient, "retrieve_token_using_auth_code")
    @patch.object(OpenIDClient, "verify_and_decode_id_token")
    def test_pkce_flow_mode_query(
        self, mock_verify_and_decode_id_token, mock_retrieve_token_using_auth_code
    ):
        """PKCE flow works as expected with query response mode"""
        mock_verify_and_decode_id_token.return_value = {
            "given_name": "john",
            "family_name": "doe",
            "email": "john@example.com",
            "preferred_username": "john",
        }
        mock_retrieve_token_using_auth_code.return_value = "id_token"
        view = UserModelOpenIDConnectViewset.as_view({"get": "callback"})
        # Simulate the code verifier being in the cache
        cache.set("pkce_123", "123")

        data = {"state": "pkce_123", "code": "auth_code"}
        request = self.factory.get("/", data=data)
        response = view(request, auth_server="pkce")
        self.assertEqual(response.status_code, 302)

        user = User.objects.get(username="john")
        self.assertEqual(user.email, "john@example.com")
        self.assertEqual(user.first_name, "john")
        self.assertEqual(user.last_name, "doe")
        mock_retrieve_token_using_auth_code.assert_called_once_with(
            "auth_code", code_verifier="123"
        )

    @override_settings(
        OPENID_CONNECT_VIEWSET_CONFIG=OPENID_CONNECT_VIEWSET_CONFIG,
        OPENID_CONNECT_AUTH_SERVERS=OPENID_CONNECT_AUTH_SERVERS,
    )
    def test_pkce_flow_cb_code_verifier_not_found(self):
        """Error returned if code verifier is not in the cache"""
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
