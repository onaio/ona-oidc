"""
Tests for the OpenID Client
"""
from django.contrib.auth import get_user_model
from django.test import TestCase
from mock import patch
from rest_framework.test import APIRequestFactory

from oidc.viewsets import OpenIDConnectViewset

User = get_user_model()


class TestOpenIDConnectViewset(TestCase):
    """
    Test class for the OpenID Connect class
    """

    def setUp(self):
        TestCase().setUp()
        self.factory = APIRequestFactory()

    def test_returns_data_entry_template_on_missing_creation_claim(self):
        """
        Test that users are redirected to the data entry
        page when username is not present in decoded token
        """
        view = OpenIDConnectViewset.as_view({"post": "callback"})
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

    def test_create_non_existing_user(self):
        """
        Test that a new user is created if the username is present and
        that the user is redirected to the `REDIRECT_AFTER_AUTH` link
        """
        view = OpenIDConnectViewset.as_view({"post": "callback"})
        with patch(
            "oidc.viewsets.OpenIDClient.verify_and_decode_id_token"
        ) as mock_func:
            mock_func.return_value = {
                "given_name": "john",
                "family_name": "doe",
                "email": "john@doe.com",
            }
            data = {"id_token": "saasdrrw.fdfdfdswg4gdfs.sadadsods", "username": "john"}
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
            }
            data = {
                "id_token": "sdadsadjaosd.sdadjiaodj.sdj91019d9",
                "username": "davis",
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
            mock_func.return_value = {"email": "jake@doe.com"}
            data = {"id_token": "sdaodjadoaj9.sdoa09dj901.sd0h091", "username": "jake"}
            request = self.factory.post("/", data=data)
            response = view(request, auth_server="default")
            self.assertEqual(response.status_code, 400)
            self.assertIn(
                "Missing required fields: family_name, given_name",
                response.rendered_content.decode("utf-8"),
            )

    def test_validates_username(self):
        """
        Test that the endpoint validates whether a username is already
        used within the system.

        i. Returns an error if same username is used
        ii. Returns an error if same username is used even if differently cased
        """
        view = OpenIDConnectViewset.as_view({"post": "callback"})
        with patch(
            "oidc.viewsets.OpenIDClient.verify_and_decode_id_token"
        ) as mock_func:
            mock_func.return_value = {
                "given_name": "john",
                "family_name": "doe",
                "email": "john@doe.com",
            }
            data = {"id_token": "saasdrrw.fdfdfdswg4gdfs.sadadsods", "username": "john"}
            request = self.factory.post("/", data=data)
            response = view(request, auth_server="default")
            # Redirects to the redirect url on successful user creation
            self.assertEqual(response.status_code, 302)

            # Test returns an error if an existing username is used
            mock_func.return_value = {
                "given_name": "jane",
                "family_name": "doe",
                "email": "jane@doe.com",
            }
            data = {"id_token": "ssad9012.fdfdfdswg4gdfs.sadadsods", "username": "john"}
            user_count = User.objects.count()
            request = self.factory.post("/", data=data)
            response = view(request, auth_server="default")
            self.assertEqual(user_count, User.objects.count())
            self.assertEqual(response.status_code, 200)
            self.assertIn(
                "Username is not available", response.rendered_content.decode("utf-8")
            )

            # Test error still returned even if username is cased differently
            data = {"id_token": "ssad9012.fdfdfdswg4gdfs.sadadsods", "username": "JoHn"}
            request = self.factory.post("/", data=data)
            response = view(request, auth_server="default")
            self.assertEqual(response.status_code, 200)
            self.assertIn(
                "Username is not available", response.rendered_content.decode("utf-8")
            )
