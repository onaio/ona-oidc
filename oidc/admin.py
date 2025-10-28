import logging
from typing import Any

from django.conf import settings
from django.contrib import admin
from django.contrib.auth import get_user_model
from django.contrib.auth.admin import UserAdmin as BaseUserAdmin
from django.core.cache import cache
from django.http import JsonResponse
from django.urls import path

import requests

import oidc.settings as default
from oidc.forms import ImportUserForm
from oidc.utils import (
    email_usename_to_url_safe,
    get_viewset_config,
    replace_characters_in_username,
    str_to_bool,
)

logger = logging.getLogger(__name__)


User = get_user_model()

OPENID_IMPORT_USER_DEFAULTS = getattr(default, "OPENID_IMPORT_USER", {})


def get_import_conf() -> dict:
    viewset_config = get_viewset_config()
    conf = OPENID_IMPORT_USER_DEFAULTS.copy()
    conf.update(getattr(settings, "OPENID_IMPORT_USER", {}))
    if "REPLACE_USERNAME_CHARACTERS" in viewset_config:
        conf["REPLACE_USERNAME_CHARACTERS"] = viewset_config[
            "REPLACE_USERNAME_CHARACTERS"
        ]
    if "USERNAME_CHAR_REPLACEMENT" in viewset_config:
        conf["USERNAME_CHAR_REPLACEMENT"] = viewset_config["USERNAME_CHAR_REPLACEMENT"]

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

    def _request_access_token(self) -> dict[str, Any]:
        """Request for a new access token."""
        config = get_import_conf()
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

    def _get_access_token(self, force_refresh: bool = False) -> str:
        """Returns access token.

        Uses cached access token unless force_refresh=True

        :param force_refresh: Force refresh of cached access token
        :returns: Cached access token if present, otherwise request one
        :rtype: string
        """
        cache_key = "oidc:import_user:token"

        if not force_refresh:
            cached = cache.get(cache_key)

            if cached:
                return cached

        data = self._request_access_token()
        token = data.get("access_token")

        if not token:
            # Defensive: malformed response
            raise requests.RequestException("Token response missing 'access_token'")

        # Respect expires_in if provided
        expires_in = int(data.get("expires_in", 3600))
        # Subtract 60s to avoid setting the extact expires_in
        timeout = max(expires_in - 60, 60)
        cache.set(cache_key, token, timeout=timeout)

        return token

    def _search_user(self, token, query) -> list:
        """Search user to import

        :param token: Access token
        :param query: Search query
        :returns: List of user(s) matching search query
        :rtype: list
        """
        config = get_import_conf()
        params = {
            config["QUERY_PARAM"]: query,
        }
        headers = {"Authorization": f"Bearer {token}"}
        response = requests.get(
            config["SEARCH_ENDPOINT"], params=params, headers=headers
        )

        if response.status_code == 401:
            # Token likely expired/invalid: force refresh and retry once
            new_token = self._get_access_token(force_refresh=True)
            headers["Authorization"] = f"Bearer {new_token}"
            response = requests.get(
                config["SEARCH_ENDPOINT"], params=params, headers=headers
            )

        response.raise_for_status()
        results = response.json()

        # If an explicit path is provided, follow it.
        path = config.get("SEARCH_RESULTS_PATH")

        if path:
            keys = path.split(".")
            cur = results

            for k in keys:
                if isinstance(cur, dict) and k in cur:
                    cur = cur[k]
                else:
                    return []
            return cur if isinstance(cur, list) else []

        return results

    def _map_user_claim_to_model(self, user_claim):
        config = get_import_conf()
        mapped_claim = {
            v: user_claim[k] for k, v in config["MAP_CLAIM_TO_MODEL"].items()
        }
        if (
            "REPLACE_USERNAME_CHARACTERS" in config
            and "USERNAME_CHAR_REPLACEMENT" in config
        ):
            mapped_claim["username"] = replace_characters_in_username(
                email_usename_to_url_safe(mapped_claim["username"]),
                config["REPLACE_USERNAME_CHARACTERS"],
                config["USERNAME_CHAR_REPLACEMENT"],
            )
        return mapped_claim

    def _parse_search_results(self, results) -> list:
        """Format search results

        :param results: Search results
        :returns: Suggestions formatted appropriately
        :rtype: list
        """

        return list(
            map(
                self._map_user_claim_to_model,
                results,
            )
        )

    def search_user(self, request):
        """Admin-protected JSON suggestions for importing a user"""
        config = get_import_conf()
        query = (request.GET.get("q") or "").strip()

        if not config or not query:
            return JsonResponse([], safe=False, status=200)

        try:
            results = self._search_user(self._get_access_token(), query)
        except requests.RequestException as exc:
            logger.exception(exc)

            return JsonResponse([], safe=False, status=200)

        suggestions = self._parse_search_results(results)

        return JsonResponse(suggestions, safe=False, status=200)


import_user_enabled = str_to_bool(get_import_conf().get("ENABLED"))

if import_user_enabled:
    # If import user feature is enabled, register our override
    try:
        admin.site.unregister(User)
    except admin.sites.NotRegistered:
        pass

    admin.site.register(User, ImportUserAdmin)
