import json
from unittest.mock import Mock, patch

from django.contrib import admin
from django.contrib.auth import get_user_model
from django.core.cache import cache
from django.test import Client, TestCase, override_settings
from django.urls import reverse

from oidc.admin import ImportUserAdmin

OPENID_IMPORT_USER = {
    "ENABLED": True,
    "TOKEN_ENDPOINT": "https://idp.example.com/oauth/token",
    "SEARCH_ENDPOINT": "https://idp.example.com/users",
    "CLIENT_ID": "cid",
    "CLIENT_SECRET": "secret",
    "SCOPE": "users.read",
    "QUERY_PARAM": "q",
    "MAP_CLAIM_TO_MODEL": {
        "email": "email",
        "given_name": "first_name",
        "family_name": "last_name",
        "preferred_username": "username",
    },
}


@override_settings(
    ROOT_URLCONF="tests.admin.urls", OPENID_IMPORT_USER=OPENID_IMPORT_USER
)
class ImportUserAdminTestCase(TestCase):
    @classmethod
    def setUpTestData(cls):
        User = get_user_model()
        cls.admin_user = User.objects.create_superuser("admin", "admin@x.com", "pass")

    def setUp(self):
        cache.clear()
        self.client = Client()
        self.client.login(username="admin", password="pass")

    def test_admin_registers_search_url(self):
        """Search user url is registered"""
        url = reverse("admin:auth_user_search")
        self.assertTrue(url.endswith("/admin/auth/user/search/"))

    @patch("oidc.admin.requests.post")
    def test_get_access_token_uses_cache(self, mock_post):
        """Get access token uses cache if not force refresh"""
        mock_post.return_value = Mock(status_code=200)
        mock_post.return_value.json = lambda: {"access_token": "abc", "expires_in": 120}
        mock_post.return_value.raise_for_status = lambda: None

        admin_obj = ImportUserAdmin(model=get_user_model(), admin_site=admin.site)

        token1 = admin_obj._get_access_token()
        self.assertEqual(token1, "abc")
        self.assertEqual(mock_post.call_count, 1)

        token2 = admin_obj._get_access_token()
        self.assertEqual(token2, "abc")
        self.assertEqual(mock_post.call_count, 1)

    @patch("oidc.admin.requests.post")
    def test_get_access_token_force_refresh(self, mock_post):
        """Get access token force refresh requests new token"""
        mock_post.return_value = Mock(status_code=200)
        mock_post.return_value.json = lambda: {
            "access_token": "fresh",
            "expires_in": 3600,
        }

        admin_obj = ImportUserAdmin(model=get_user_model(), admin_site=admin.site)
        token = admin_obj._get_access_token(force_refresh=True)
        self.assertEqual(token, "fresh")
        self.assertEqual(mock_post.call_count, 1)
        mock_post.assert_called_with(
            "https://idp.example.com/oauth/token",
            data={
                "grant_type": "client_credentials",
                "scope": "users.read",
                "client_id": "cid",
                "client_secret": "secret",
            },
        )

    @patch("oidc.admin.requests.post")
    @patch("oidc.admin.requests.get")
    def test_search_user_retries_on_401(self, mock_get, mock_post):
        """Search user retries on 401 requests new token"""
        admin_obj = ImportUserAdmin(model=get_user_model(), admin_site=admin.site)

        first = Mock(status_code=401)
        first.raise_for_status = Mock(side_effect=Exception("should not be called"))
        second = Mock(status_code=200)
        second.json = lambda: [
            {
                "email": "a@b.com",
                "given_name": "A",
                "family_name": "B",
                "preferred_username": "ab",
            }
        ]
        mock_get.side_effect = [first, second]

        mock_post.return_value = Mock(status_code=200)
        mock_post.return_value.json = lambda: {
            "access_token": "newtok",
            "expires_in": 3600,
        }

        out = admin_obj._search_user(token="oldtok", query="ab")
        self.assertEqual(out[0]["email"], "a@b.com")
        self.assertEqual(mock_get.call_count, 2)
        self.assertEqual(mock_post.call_count, 1)

    def test_parse_search_results_mapping(self):
        """Map claim to model fields"""
        admin_obj = ImportUserAdmin(model=get_user_model(), admin_site=admin.site)
        raw = [
            {
                "email": "x@y.com",
                "given_name": "X",
                "family_name": "Y",
                "preferred_username": "xy",
            }
        ]
        parsed = admin_obj._parse_search_results(raw)
        self.assertEqual(
            parsed,
            [
                {
                    "email": "x@y.com",
                    "first_name": "X",
                    "last_name": "Y",
                    "username": "xy",
                }
            ],
        )

    @patch("oidc.admin.requests.get")
    @patch("oidc.admin.requests.post")
    def test_search_user_view_json(self, mock_post, mock_get):
        """Search user view json"""
        mock_post.return_value = Mock(status_code=200)
        mock_post.return_value.json = lambda: {
            "access_token": "tok",
            "expires_in": 3600,
        }

        resp_get = Mock(status_code=200)
        resp_get.json = lambda: [
            {
                "email": "a@b.com",
                "given_name": "A",
                "family_name": "B",
                "preferred_username": "ab",
            }
        ]
        mock_get.return_value = resp_get

        url = reverse("admin:auth_user_search")
        r = self.client.get(url, {"q": "ab"})
        self.assertEqual(r.status_code, 200)
        data = json.loads(r.content.decode("utf-8"))
        self.assertEqual(
            data,
            [
                {
                    "email": "a@b.com",
                    "first_name": "A",
                    "last_name": "B",
                    "username": "ab",
                }
            ],
        )
        mock_get.assert_called_with(
            "https://idp.example.com/users",
            params={"q": "ab"},
            headers={"Authorization": "Bearer tok"},
        )

    def test_search_user_view_empty_query_returns_empty(self):
        """Search user view empty query returns empty"""
        url = reverse("admin:auth_user_search")
        r = self.client.get(url, {"q": ""})
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.json(), [])

    @patch("oidc.admin.requests.get")
    @patch("oidc.admin.requests.post")
    def test_search_results_path(self, mock_post, mock_get):
        """Search results path works if specified"""
        admin_obj = ImportUserAdmin(model=get_user_model(), admin_site=admin.site)

        mock_post.return_value = Mock(status_code=200)
        mock_post.return_value.json = lambda: {
            "access_token": "tok",
            "expires_in": 3600,
        }

        # Works with zero nested path
        with override_settings(
            OPENID_IMPORT_USER={
                **OPENID_IMPORT_USER,
                "SEARCH_RESULTS_PATH": "data",
            }
        ):
            mock_get.return_value = Mock(status_code=200)
            mock_get.return_value.json = lambda: {
                "data": [
                    {
                        "email": "a@b.com",
                        "given_name": "A",
                        "family_name": "B",
                        "preferred_username": "ab",
                    }
                ]
            }

            out = admin_obj._search_user(token="tok", query="ab")
            self.assertEqual(out[0]["email"], "a@b.com")

        # Works with nested path
        mock_get.reset_mock()
        with override_settings(
            OPENID_IMPORT_USER={
                **OPENID_IMPORT_USER,
                "SEARCH_RESULTS_PATH": "data.results",
            }
        ):
            mock_get.return_value = Mock(status_code=200)
            mock_get.return_value.json = lambda: {
                "data": {
                    "results": [
                        {
                            "email": "a@b.com",
                            "given_name": "A",
                            "family_name": "B",
                            "preferred_username": "ab",
                        }
                    ]
                }
            }

            out = admin_obj._search_user(token="tok", query="ab")
            self.assertEqual(out[0]["email"], "a@b.com")
