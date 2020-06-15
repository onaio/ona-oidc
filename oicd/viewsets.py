"""
OICD Viewsets module
"""
from typing import Optional

import jwt
import oicd.settings as default
from django.conf import settings
from django.contrib.auth import get_user_model, login
from django.db.models import QuerySet
from django.http import HttpRequest, HttpResponse, HttpResponseRedirect
from django.utils.translation import ugettext as _
from oicd.client import OpenIDClient
from oicd.client import config as auth_config
from rest_framework import permissions, status, viewsets
from rest_framework.decorators import action
from rest_framework.renderers import JSONRenderer, TemplateHTMLRenderer
from rest_framework.response import Response

config = getattr(settings, "OPENID_CONNECT_VIEWSET_CONFIG", {})
default_config = getattr(default, "OPENID_CONNECT_VIEWSET_CONFIG", {})


class OpenIDConnectViewset(viewsets.ViewSet):
    """
    OpenIDConnectViewSet: Handles OpenID connect authentication.
    """

    permission_classes = [permissions.AllowAny]
    renderer_classes = [JSONRenderer, TemplateHTMLRenderer]

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.jwt = config.get("JWT_SECRET_KEY", "")
        self.user_creation_claims = (
            config.get("USER_CREATION_CLAIMS") or default_config["USER_CREATION_CLAIMS"]
        )
        self.map_claim_to_model = (
            config.get("MAP_CLAIM_TO_MODEL") or default_config["MAP_CLAIM_TO_MODEL"]
        )
        self.use_sso = config.get("USE_SSO_COOKIE", True)
        self.sso_cookie = (
            config.get("SSO_COOKIE_DATA") or default_config["SSO_COOKIE_DATA"]
        )
        self.jwt_algorithm = (
            config.get("JWT_ALGORITHM") or default_config["JWT_ALGORITHM"]
        )
        self.cookie_max_age = config.get("SSO_COOKIE_MAX_AGE")
        self.cookie_domain = config.get("SSO_COOKIE_DOMAIN", "localhost")
        self.use_auth_backend = config.get("USE_AUTH_BACKEND", False)
        self.auth_backend = config.get(
            "AUTH_BACKEND", "django.contrib.auth.backends.ModelBackend"
        )

    def _get_client(self, auth_server: str) -> Optional[OpenIDClient]:
        if auth_server in auth_config:
            return OpenIDClient(auth_server)
        return None

    @action(methods=["GET"], detail=False)
    def login(self, request: HttpRequest, **kwargs: dict) -> HttpResponse:
        if self._get_client(**kwargs):
            return self._get_client(**kwargs).login()
        return Response(
            _("Unable to process OpenID connect login request."),
            status=status.HTTP_400_BAD_REQUEST,
        )

    @action(methods=["GET"], detail=False)
    def logout(self, request: HttpRequest, **kwargs: dict) -> HttpResponse:
        if self._get_client(**kwargs):
            return self._get_client(**kwargs).logout()
        return Response(
            _("Unable to process OpenID connect logout request."),
            status=status.HTTP_400_BAD_REQUEST,
        )

    @action(methods=["POST"], detail=False)
    def callback(self, request: HttpRequest, **kwargs: dict) -> HttpResponse:
        if self._get_client(**kwargs):
            client = self._get_client(**kwargs)
            if request.POST.get("id_token") or "username" in request.POST:
                user_data = request.POST.copy()
                user_model = get_user_model()
                user = None

                if user_data.get("id_token"):
                    decoded_token = client.verify_and_decode_id_token(
                        user_data.pop("id_token")
                    )
                    email = decoded_token.get("email")
                    if user_model.objects.filter(email=email).count() > 0:
                        user = user_model.objects.get(email=email)
                    else:
                        user_data.update(decoded_token)

                if not user and user_data.get("username"):
                    data = {}
                    for k, v in user_data.items():
                        if k in self.user_creation_claims:
                            data[self.map_claim_to_model.get(k)] = v

                    if (
                        user_model.objects.filter(
                            username__iexact=data.get("username")
                        ).count()
                        == 0
                    ):
                        if not data.get("first_name") and not data.get("last_name"):
                            return Response(
                                _("Missing required fields: family_name, given_name"),
                                status=status.HTTP_400_BAD_REQUEST,
                            )

                        if not data.get("first_name"):
                            data["first_name"] = data.get("last_name")

                        user = user_model.objects.create(**data)
                    else:
                        user_data["error"] = "Username is not available"

                if user:
                    if isinstance(user, QuerySet):
                        user = user.first()
                    response = HttpResponseRedirect(config.get("REDIRECT_AFTER_AUTH"))
                    if self.use_sso:
                        sso_cookie = jwt.encode(
                            {"email": getattr(user, self.sso_cookie, "email")},
                            config.get("JWT_SECRET_KEY"),
                            config.get("JWT_ALGORITHM"),
                        )
                        response.set_cookie(
                            "SSO",
                            value=sso_cookie.decode("utf-8"),
                            max_age=self.cookie_max_age,
                            domain=self.cookie_domain,
                        )

                    if self.use_auth_backend:
                        login(
                            request, user, backend=self.auth_backend,
                        )
                    return response
                else:
                    existing_data = {
                        k: v
                        for k, v in user_data.items()
                        if k in self.user_creation_claims or k == "error"
                    }
                    return Response(
                        {"existing_data": existing_data},
                        template_name="oicd/oidc_user_data_entry.html",
                    )
        return Response(
            _("Unable to process OpenID connect authentication request."),
            status=status.HTTP_400_BAD_REQUEST,
        )
