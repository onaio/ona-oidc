"""
URL Configuration file for ona-oidc
"""

from django.conf import settings
from django.urls import re_path

from oidc.utils import str_to_bool
from oidc.viewsets import RapidProOpenIDConnectViewset, UserModelOpenIDConnectViewset

app_name = "oidc"

viewset_class = UserModelOpenIDConnectViewset

config = getattr(settings, "OPENID_CONNECT_VIEWSET_CONFIG", {})
if str_to_bool(config.get("USE_RAPIDPRO_VIEWSET", False)):
    viewset_class = RapidProOpenIDConnectViewset

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
        r"^oidc/(?P<auth_server>\w+)/account$",
        viewset_class.as_view({"post": "account"}),
        name="openid_connect_account",
    ),
    re_path(
        r"^oidc/(?P<auth_server>\w+)/sessions$",
        viewset_class.as_view(
            {"get": "sessions_list", "delete": "sessions_revoke_others"}
        ),
        name="openid_connect_sessions",
    ),
    re_path(
        r"^oidc/(?P<auth_server>\w+)/sessions/(?P<session_id>[a-zA-Z0-9._-]+)$",
        viewset_class.as_view({"delete": "sessions_revoke_one"}),
        name="openid_connect_sessions_revoke_one",
    ),
    re_path(
        r"^oidc/(?P<auth_server>\w+)/linked-accounts$",
        viewset_class.as_view({"get": "linked_list"}),
        name="openid_connect_linked_list",
    ),
    re_path(
        r"^oidc/(?P<auth_server>\w+)/linked-accounts/(?P<provider>[^/]+)/link-url$",
        viewset_class.as_view({"get": "linked_link_url"}),
        name="openid_connect_linked_link_url",
    ),
    re_path(
        r"^oidc/(?P<auth_server>\w+)/linked-accounts/(?P<provider>[^/]+)$",
        viewset_class.as_view({"delete": "linked_unlink"}),
        name="openid_connect_linked_unlink",
    ),
    re_path(
        r"^oidc/(?P<auth_server>\w+)/credentials$",
        viewset_class.as_view({"get": "credentials_list"}),
        name="openid_connect_credentials",
    ),
]
