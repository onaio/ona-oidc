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

from .client import OpenIDClient

config = getattr(settings, "OPENID_CONNECT_VIEWSET_CONFIG", {})


class OpenIDConnectViewset(viewsets.ViewSet):
    """
    OpenIDConnectViewSet: Handles OpenID connect authentication.
    """

    permission_classes = config["PERMISSION_CLASSES"]
    authentication_classes = config["PERMISSION_CLASSES"]

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
                if config["USER_CREATION_CLAIMS"] in user_data and not user:
                    user_default = {
                        config["MAP_CLAIM_TO_MODEL"].get("k"): v
                        for k, v in user_data.items()
                        if k in config["USER_CREATION_CLAIMS"]
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
                    response = HttpResponseRedirect(config["REDIRECT_AFTER_AUTH"])
                    if config["USE_SSO_COOKIE"]:
                        sso_cookie = jwt.encode(
                            getattr(user, config["SSO_COOKIE_DATA"], "email"),
                            config["JWT_SECRET_KEY"],
                            config["JWT_ALGORITHM"],
                        )
                        response.set_cookie(
                            "SSO",
                            value=sso_cookie.decode("utf-8"),
                            max_age=config["SSO_COOKIE_MAX_AGE"],
                            domain=config["SSO_COOKIE_DOMAIN"],
                        )
                    return response
                else:
                    claims = config["USER_CREATION_CLAIMS"]
                    if "email" not in claims:
                        claims.append("email")
                    existing_data = {k: v for k, v in user_data if k in claims}
                    return Response(
                        existing_data, template_name="oidc_user_data_entry.html"
                    )
        return Response(
            "Unable to process OpenID connect authentication request.",
            status=status.HTTP_400_BAD_REQUEST,
        )
