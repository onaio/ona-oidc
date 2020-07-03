"""
URL Configuration file for ona-oidc
"""
from django.conf import settings
from django.urls import re_path

from oidc.viewsets import RapidProOpenIDConnectViewset, UserModelOpenIDConnectViewset

app_name = "oidc"

viewset_class = UserModelOpenIDConnectViewset

config = getattr(settings, "OPENID_CONNECT_VIEWSET_CONFIG", {})
if config.get("USE_RAPIDPRO_VIEWSET", False):
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
]
