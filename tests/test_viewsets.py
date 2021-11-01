"""
Tests for the OpenID Client
"""
from django.contrib.auth import get_user_model
from django.test import TestCase
from django.test.utils import override_settings

from mock import MagicMock, patch
from rest_framework.test import APIRequestFactory

from oidc.viewsets import UserModelOpenIDConnectViewset

User = get_user_model()

OPENID_CONNECT_AUTH_SERVERS = {
    "default": {
        "AUTHORIZATION_ENDPOINT": "example.com/oauth2/v2.0/authorize",
        "CLIENT_ID": "client",
        "JWKS_ENDPOINT": "example.com/discovery/v2.0/keys",
        "SCOPE": "openid profile",
        "TOKEN_ENDPOINT": "example.com/oauth2/v2.0/token",
        "END_SESSION_ENDPOINT": "http://localhost:3000",
        "REDIRECT_URI": "http://localhost:8000/oidc/msft/callback",
        "RESPONSE_TYPE": "code",
        "RESPONSE_MODE": "form_post",
        "USE_NONCES": False,
    }
}
OPENID_CONNECT_VIEWSET_CONFIG = {
    "REQUIRED_USER_CREATION_FIELDS": ["email", "first_name", "username"],
    "USER_CREATION_FIELDS": ["email", "first_name", "last_name", "username"],
    "MAP_CLAIM_TO_MODEL": {
        "given_name": "first_name",
        "family_name": "last_name",
        "sub": "email",
    },
    "USER_DEFAULTS": {
        "default": {"is_active": False},
        "^.*@ona.io$": {"is_active": True}
    },
    "SPLIT_NAME_CLAIM": True,
    "USER_UNIQUE_FILTER_FIELD": "email",
    "SSO_COOKIE_DATA": "email",
    "JWT_ALGORITHM": "HS256",
    "JWT_SECRET_KEY": "abc",
}


class TestUserModelOpenIDConnectViewset(TestCase):
    """
    Test class for the OpenID Connect class
    """

    def setUp(self):
        TestCase().setUp()
        self.factory = APIRequestFactory()

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
            self.assertEqual(response.template_name, "oidc/oidc_unrecoverable_error.html")
            self.assertEqual(
                response.data.get('error'),
                'Missing required fields: first_name')

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
                response.rendered_content.decode("utf-8")
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
            self.assertEqual(user.is_active, True)

            # User who aren't from @ona.io should have is_active set to False
            mock_func.return_value = {
                "given_name": "john",
                "family_name": "doe",
                "sub": "john@example.com",
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
            self.assertEqual(user.email, "john@example.com")
            self.assertEqual(user.is_active, False)
