"""
URL Configuration file for ona-oidc
"""
from django.urls import re_path

from oidc.viewsets import OpenIDConnectViewset

app_name = "oidc"
urlpatterns = [
    re_path(
        r"^oidc/(?P<auth_server>\w+)/login",
        OpenIDConnectViewset.as_view({"get": "login"}),
        name="openid_connect_login",
    ),
    re_path(
        r"^oidc/(?P<auth_server>\w+)/callback",
        OpenIDConnectViewset.as_view({"get": "callback", "post": "callback"}),
        name="openid_connect_callback",
    ),
    re_path(
        r"^oidc/(?P<auth_server>\w+)/logout",
        OpenIDConnectViewset.as_view({"get": "logout"}),
        name="openid_connect_logout",
    ),
]
