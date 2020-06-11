"""
OICD Viewsets module
"""
from typing import Optional
import jwt

from django.contrib.auth import get_user_model, login
from django.conf import settings
from django.http import HttpResponseRedirect, HttpRequest, HttpResponse
from rest_framework import viewsets, status
from rest_framework.response import Response
from rest_framework.decorators import action

from oicd.client import OpenIDClient
import oicd.settings as default

config = getattr(settings, "OPENID_CONNECT_VIEWSET_CONFIG", {})
default_config = getattr(default, "OPENID_CONNECT_VIEWSET_CONFIG", {})


def _import_classes(class_list: list) -> list:
    final_class_list = []
    for klass in class_list:
        module = __import__(klass.rsplit(".", 1)[0])
        kls = getattr(module, klass.rsplit(".", 1)[1])
        final_class_list.append(kls)
    return final_class_list


class OpenIDConnectViewset(viewsets.ViewSet):
    """
    OpenIDConnectViewSet: Handles OpenID connect authentication.
    """

    permission_classes = _import_classes(config.get("PERMISSION_CLASSES", []))
    authentication_classes = _import_classes(config.get("AUTHENTICATION_CLASSES", []))
    renderer_classes = _import_classes(
        config.get("RENDERER_CLASSES", default_config["RENDERER_CLASSES"])
    )

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.jwt = config.get("JWT_SECRET_KEY", "")
        self.user_creation_claims = (
            config.get("USER_CREATION_CLAIMS") or default_config["USER_CREATION_CLAIMS"]
        )
        self.map_claim_to_model = (
            config.get("MAP_CLAIM_TO_MODEL") or default_config["MAP_CLAIM_TO_MODEL"]
        )
        self.use_sso = config.get("USE_SSO_COOKIE", False)
        self.sso_cookie = (
            config.get("SSO_COOKIE_DATA") or default_config["SSO_COOKIE_DATA"]
        )
        self.jwt_algorithm = (
            config.get("JWT_ALGORITHM") or default_config["JWT_ALGORITHM"]
        )
        self.cookie_max_age = config.get("SSO_COOKIE_MAX_AGE")
        self.cookie_domain = config.get("SSO_COOKIE_DOMAIN", "localhost")

    def _get_client(self, auth_server: str) -> Optional[OpenIDClient]:
        if auth_server in config:
            return OpenIDClient(auth_server)
        return None

    @action(methods=["GET"], detail=False)
    def login(self, request: HttpRequest, **kwargs: dict) -> HttpResponse:
        if self._get_client(**kwargs):
            return self._get_client(**kwargs).login()
        return Response(
            "Unable to process OpenID connect login request.",
            status=status.HTTP_400_BAD_REQUEST,
        )

    @action(methods=["GET"], detail=False)
    def logout(self, request: HttpRequest, **kwargs: dict) -> HttpResponse:
        if self._get_client(**kwargs):
            return self._get_client(**kwargs).logout()
        return Response(
            "Unable to process OpenID connect logout request.",
            status=status.HTTP_400_BAD_REQUEST,
        )

    @action(methods=["GET", "POST"], detail=False)
    def callback(self, request: HttpRequest, **kwargs: dict) -> HttpResponse:
        if self._get_client(**kwargs):
            client = self._get_client(**kwargs)
            if request.POST.get("id_token"):
                decoded_token = client.verify_and_decode_id_token(
                    request.POST.get("id_token")
                )
                email = decoded_token.get("email")
                user_model = get_user_model()
                user = user_model.objects.get(email=email)
                user_data = request.POST.get("user_data") or decoded_token
                if self.user_creation_claims in user_data and not user:
                    user_default = {
                        self.map_claim_to_model.get("k"): v
                        for k, v in user_data.items()
                        if k in self.user_creation_claims
                    }
                    if (
                        not user_model.object.filter(
                            username=user_default.get("username")
                        ).count()
                        > 0
                    ):
                        user = user_model.objects.create(user_default)
                    user_data[
                        "error"
                    ] = f"Username \"{user_default.get('username')}\" is not available"

                if user:
                    login(request, user)
                    response = HttpResponseRedirect(config.get("REDIRECT_AFTER_AUTH"))
                    if self.use_sso:
                        sso_cookie = jwt.encode(
                            getattr(user, self.sso_cookie, "email"),
                            config.get("JWT_SECRET_KEY"),
                            config.get("JWT_ALGORITHM"),
                        )
                        response.set_cookie(
                            "SSO",
                            value=sso_cookie.decode("utf-8"),
                            max_age=self.cookie_max_age,
                            domain=self.cookie_domain,
                        )
                    return response
                else:
                    existing_data = {
                        k: v for k, v in user_data if k in self.user_creation_claims
                    }
                    return Response(
                        existing_data, template_name="oidc_user_data_entry.html"
                    )
        return Response(
            "Unable to process OpenID connect authentication request.",
            status=status.HTTP_400_BAD_REQUEST,
        )
