"""
Tests for the OpenID Client
"""
from django.test import TestCase
from mock import patch
from oicd.viewsets import OpenIDConnectViewset
from rest_framework.test import APIRequestFactory


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
        page when missing a required user creation claim
        """
        view = OpenIDConnectViewset.as_view({"post": "callback"})
        with patch(
            "oicd.viewsets.OpenIDClient.verify_and_decode_id_token"
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
            self.assertEqual(response.template_name, "oicd/oidc_user_data_entry.html")
