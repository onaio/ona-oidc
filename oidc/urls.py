"""
URL Configuration file for ona-oidc
"""

from django.conf import settings
from django.urls import re_path
from django.utils.module_loading import import_string

from rest_framework.renderers import JSONRenderer

from oidc.permissions import IsCsrfSafeAccountRequest
from oidc.utils import str_to_bool
from oidc.viewsets import RapidProOpenIDConnectViewset, UserModelOpenIDConnectViewset

app_name = "oidc"


def get_viewset_class():
    """The viewset these URLs route to.

    ``VIEWSET_CLASS`` (a dotted path) lets a deployment route to its own
    subclass while still using ``include("oidc.urls")``. Without it, changing
    this one name means copying the whole URLconf, and then mirroring every
    route and every ``as_view()`` kwarg -- including the account-proxy CSRF
    gate below -- by hand, forever.

    ``USE_RAPIDPRO_VIEWSET`` is the older boolean form and still works.
    """
    config = getattr(settings, "OPENID_CONNECT_VIEWSET_CONFIG", {})
    dotted_path = config.get("VIEWSET_CLASS")
    if dotted_path:
        return import_string(dotted_path)
    if str_to_bool(config.get("USE_RAPIDPRO_VIEWSET", False)):
        return RapidProOpenIDConnectViewset
    return UserModelOpenIDConnectViewset


viewset_class = get_viewset_class()

# Every account-proxy route must use these. Dropping authentication_classes
# without IsCsrfSafeAccountRequest leaves the route CSRF-open; see the
# "Keycloak Account REST proxy" section of the README.
_ACCOUNT_PROXY_VIEW_KWARGS = {
    "authentication_classes": [],
    "permission_classes": [IsCsrfSafeAccountRequest],
    "renderer_classes": [JSONRenderer],
}

urlpatterns = [
    re_path(
        r"^oidc/(?P<auth_server>\w+)/login",
        viewset_class.as_view({"get": "login"}),
        name="openid_connect_login",
    ),
    re_path(
        r"^oidc/(?P<auth_server>\w+)/callback",
        viewset_class.as_view({"get": "callback", "post": "callback"}),
        name="openid_connect_callback",
    ),
    re_path(
        r"^oidc/(?P<auth_server>\w+)/logout",
        viewset_class.as_view({"get": "logout"}),
        name="openid_connect_logout",
    ),
    re_path(
        r"^oidc/(?P<auth_server>\w+)/session$",
        viewset_class.as_view(
            {"get": "session"},
            authentication_classes=[],
            renderer_classes=[JSONRenderer],
        ),
        name="openid_connect_session",
    ),
    re_path(
        r"^oidc/(?P<auth_server>\w+)/account$",
        viewset_class.as_view({"post": "account"}, **_ACCOUNT_PROXY_VIEW_KWARGS),
        name="openid_connect_account",
    ),
    re_path(
        r"^oidc/(?P<auth_server>\w+)/sessions$",
        viewset_class.as_view(
            {"get": "sessions_list", "delete": "sessions_revoke_others"},
            **_ACCOUNT_PROXY_VIEW_KWARGS,
        ),
        name="openid_connect_sessions",
    ),
    re_path(
        r"^oidc/(?P<auth_server>\w+)/sessions/(?P<session_id>[a-zA-Z0-9._-]+)$",
        viewset_class.as_view(
            {"delete": "sessions_revoke_one"}, **_ACCOUNT_PROXY_VIEW_KWARGS
        ),
        name="openid_connect_sessions_revoke_one",
    ),
    re_path(
        r"^oidc/(?P<auth_server>\w+)/linked-accounts$",
        viewset_class.as_view({"get": "linked_list"}, **_ACCOUNT_PROXY_VIEW_KWARGS),
        name="openid_connect_linked_list",
    ),
    re_path(
        r"^oidc/(?P<auth_server>\w+)/linked-accounts/(?P<provider>[^/]+)/link-url$",
        viewset_class.as_view({"get": "linked_link_url"}, **_ACCOUNT_PROXY_VIEW_KWARGS),
        name="openid_connect_linked_link_url",
    ),
    re_path(
        r"^oidc/(?P<auth_server>\w+)/linked-accounts/(?P<provider>[^/]+)$",
        viewset_class.as_view(
            {"delete": "linked_unlink"}, **_ACCOUNT_PROXY_VIEW_KWARGS
        ),
        name="openid_connect_linked_unlink",
    ),
    re_path(
        r"^oidc/(?P<auth_server>\w+)/credentials$",
        viewset_class.as_view(
            {"get": "credentials_list"}, **_ACCOUNT_PROXY_VIEW_KWARGS
        ),
        name="openid_connect_credentials",
    ),
]
