import logging

from django.conf import settings
from django.contrib import admin
from django.contrib.auth import get_user_model
from django.contrib.auth.admin import UserAdmin as BaseUserAdmin
from django.http import JsonResponse
from django.urls import path

import requests

import oidc.settings as default
from oidc.forms import ImportUserForm
from oidc.utils import str_to_bool

logger = logging.getLogger(__name__)


User = get_user_model()

OPENID_IMPORT_USER_DEFAULTS = getattr(default, "OPENID_IMPORT_USER", {})


def get_import_conf() -> dict:
    conf = OPENID_IMPORT_USER_DEFAULTS.copy()
    conf.update(getattr(settings, "OPENID_IMPORT_USER", {}))

    return conf


class ImportUserAdmin(BaseUserAdmin):
    add_form_template = "admin/auth/user/import_form.html"
    add_form = ImportUserForm
    add_fieldsets = (
        (
            None,
            {
                "classes": ("wide",),
                "fields": ("username", "first_name", "last_name", "email"),
            },
        ),
    )

    def get_urls(self):
        urls = super().get_urls()
        # Add URL /admin/auth/user/search
        custom = [
            path(
                "search/",
                self.admin_site.admin_view(self.search_user),
                name="auth_user_search",
            ),
        ]
        # Insert before the default urls so {% url 'admin:auth_user_search' %} resolves
        return custom + urls

    def _get_access_token(self):
        """Get access token required for importing users"""
        config = get_import_conf()

        try:
            response = requests.post(
                config["TOKEN_ENDPOINT"],
                data={
                    "grant_type": "client_credentials",
                    "scope": config["SCOPE"],
                    "client_id": config["CLIENT_ID"],
                    "client_secret": config["CLIENT_SECRET"],
                },
            )
            response.raise_for_status()
            return response.json()
        except (requests.RequestException, ValueError) as exc:
            logger.exception(exc)

            raise

    def _search_user(self, token, query):
        """Search user to import

        :param token: Access token
        :param query: Search query
        :returns: List of users to import
        :rtype: list
        """
        config = get_import_conf()
        params = {
            config["QUERY_PARAM"]: query,
        }
        headers = {"Authorization": f"Bearer {token}"}

        try:
            response = requests.get(
                config["SEARCH_ENDPOINT"], params=params, headers=headers
            )
            response.raise_for_status()
            return response.json()
        except (requests.RequestException, ValueError) as exc:
            logger.exception(exc)

            raise

    def _parse_search_suggestions(self, users):
        config = get_import_conf()

        return list(
            map(
                lambda user: {
                    v: user[k] for k, v in config["EXTERNAL_TO_MODEL"].items()
                },
                users,
            )
        )

    def search_user(self, request):
        """Admin-protected JSON suggestions for importing a user"""
        config = get_import_conf()
        query = (request.GET.get("q") or "").strip()

        if not config or not query:
            return JsonResponse([], safe=False, status=200)

        return self._dummy_search(query)

        # Get access token
        try:
            token = self._get_access_token()
        except requests.RequestException:
            return JsonResponse([], safe=False, status=200)

        # Make API call to search user
        try:
            suggestions = self._search_user(token["access_token"], query)
        except requests.RequestException:
            return JsonResponse([], safe=False, status=200)

        suggestions = self._parse_search_suggestions(suggestions)

        return JsonResponse(suggestions, safe=False, status=200)

    def _dummy_search(self, q: str) -> list[dict]:
        """Return filtered dummy results (case-insensitive contains across a few fields)."""
        cfg = get_import_conf()
        raw = [
            {
                "id": 1,
                "given_name": "Jane",
                "family_name": "Doe",
                "email": "jane@example.com",
                "preferred_username": "jane",
            },
            {
                "id": 2,
                "given_name": "John",
                "family_name": "Kamau",
                "email": "john.kamau@example.com",
                "preferred_username": "jkamau",
            },
            {
                "id": 3,
                "given_name": "Amina",
                "family_name": "Ali",
                "email": "amina.ali@example.org",
                "preferred_username": "aali",
            },
        ]
        ql = q.lower()

        def matches(u: dict) -> bool:
            return any(
                (u.get("given_name", "") or "").lower().find(ql) >= 0
                or (u.get("family_name", "") or "").lower().find(ql) >= 0
                or (u.get("preferred_username", "") or "").lower().find(ql) >= 0
                or (u.get("email", "") or "").lower().find(ql) >= 0
            )

        filtered = [u for u in raw if matches(u)]
        limit = int(cfg.get("LIMIT", 10) or 10)
        return filtered[:limit]


import_user_enabled = str_to_bool(get_import_conf().get("ENABLED"))

if import_user_enabled:
    # If import user feature is enabled, register our override
    try:
        admin.site.unregister(User)
    except admin.sites.NotRegistered:
        pass

    admin.site.register(User, ImportUserAdmin)
