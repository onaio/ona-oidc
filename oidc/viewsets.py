"""
oidc Viewsets module
"""
import importlib
from typing import Optional

import jwt
from django.conf import settings
from django.contrib.auth import get_user_model, login
from django.http import (
    HttpRequest,
    HttpResponse,
    HttpResponseBadRequest,
    HttpResponseRedirect,
)
from django.utils.translation import ugettext as _
from rest_framework import permissions, status, viewsets
from rest_framework.decorators import action
from rest_framework.renderers import JSONRenderer, TemplateHTMLRenderer
from rest_framework.response import Response

import oidc.settings as default
from oidc.client import OpenIDClient
from oidc.client import config as auth_config

config = getattr(settings, "OPENID_CONNECT_VIEWSET_CONFIG", {})
default_config = getattr(default, "OPENID_CONNECT_VIEWSET_CONFIG", {})


class BaseOpenIDConnectViewset(viewsets.ViewSet):
    """
    BaseOpenIDConnectViewset: Base viewset that implements login and logout
    Open ID Connect Functionality.
    """

    permission_classes = [permissions.AllowAny]
    renderer_classes = [JSONRenderer, TemplateHTMLRenderer]
    user_model = None

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
        self.unique_user_filter_field = (
            config.get("USER_UNIQUE_FILTER_FIELD")
            or default_config["USER_UNIQUE_FILTER_FIELD"]
        )

    def _get_client(self, auth_server: str) -> Optional[OpenIDClient]:
        if auth_server in auth_config:
            return OpenIDClient(auth_server)
        return None

    @action(methods=["GET"], detail=False)
    def login(self, request: HttpRequest, **kwargs: dict) -> HttpResponse:
        if self._get_client(**kwargs):
            return self._get_client(**kwargs).login()
        return HttpResponseBadRequest(
            _("Unable to process OpenID connect login request."),
        )

    @action(methods=["GET"], detail=False)
    def logout(self, request: HttpRequest, **kwargs: dict) -> HttpResponse:
        if self._get_client(**kwargs):
            return self._get_client(**kwargs).logout()
        return HttpResponseBadRequest(
            _("Unable to process OpenID connect logout request."),
        )

    def _check_user_exists(self, user_data: dict) -> bool:
        """
        Helper function that checks if a user exists
        """
        if user_data.get(self.unique_user_filter_field):
            field_value = user_data.get(self.unique_user_filter_field)
            field = self.unique_user_filter_field + "__iexact"
            return self.user_model.objects.filter(**{field: field_value}).count() > 0
        return True

    def generate_successful_response(self, request, user) -> HttpResponse:
        """
        Generates a success response for a successful Open ID Connect
        Authentication request
        """
        response = HttpResponseRedirect(config.get("REDIRECT_AFTER_AUTH"))

        if self.use_auth_backend:
            login(request, user, backend=self.auth_backend)

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

        return response

    def map_claims_to_model_field(self, user_data) -> dict:
        """
        Maps claims to the appropriate field for model ingestion
        """
        data = {}
        for k, v in user_data.items():
            if k in self.user_creation_claims:
                data[self.map_claim_to_model[k]] = v
        return data

    @action(methods=["POST"], detail=False)
    def callback(self, request: HttpRequest, **kwargs: dict) -> HttpResponse:
        client = self._get_client(**kwargs)
        if self._get_client(**kwargs):
            user_data = request.POST.dict()
            id_token = user_data.pop("id_token") if "id_token" in user_data else None
            code = user_data.pop("code") if "code" in user_data else None

            if code and not id_token:
                id_token = client.retrieve_token_using_auth_code(code)

            if id_token:
                user = None

                # Verify, decode and retrieve user information from ID Token
                decoded_token = client.verify_and_decode_id_token(id_token)
                email = decoded_token.get("email")

                if self.user_model.objects.filter(email=email).count() > 0:
                    user = self.user_model.objects.get(email=email)
                else:
                    user_data.update(self.map_claims_to_model_field(decoded_token))
                    if "username" not in user_data or self._check_user_exists(
                        user_data
                    ):
                        # If username is not present within the user_data
                        # Return the data_entry template so the user can
                        # input the username manually.
                        return Response(
                            {
                                "id_token": id_token,
                                "error": _("Username is not available"),
                            },
                            template_name="oidc/oidc_user_data_entry.html",
                        )

                if not user and "username" in user_data:
                    if not user_data.get("first_name") and not user_data.get(
                        "last_name"
                    ):
                        return Response(
                            _("Missing required fields: family_name, given_name"),
                            status=status.HTTP_400_BAD_REQUEST,
                        )
                    elif not user_data.get("first_name"):
                        user_data["first_name"] = user_data.get("last_name")

                    user = self.create_login_user(user_data)

                if user:
                    return self.generate_successful_response(request, user)
        return HttpResponseBadRequest(
            _("Unable to process OpenID connect authentication request."),
        )

    def create_login_user(self, user_data: dict):
        """
        Function used to create a login user from the information retrieved
        from the ID Token
        """
        raise NotImplementedError()


class UserModelOpenIDConnectViewset(BaseOpenIDConnectViewset):
    """
    OpenID Connect Viewset that utilizes the user model to create/retrieve
    request user account
    """

    user_model = get_user_model()

    def create_login_user(self, user_data: dict):
        return self.user_model.objects.create(**user_data)


class RapidProOpenIDConnectViewset(BaseOpenIDConnectViewset):
    """
    OpenID Connect Viewset tailored to work with
    RapidPro(https://github.com/rapidpro/rapidpro)
    """

    user_model = get_user_model()

    def create_login_user(self, user_data: dict):
        Org = importlib.import_module("temba").orgs.models.Org
        timezone = importlib.import_module("pytz").timezone
        org_name = user_data.pop("username")
        user_data["username"] = user_data.get("email")

        org_data = {
            "name": org_name,
            "slug": Org.get_unique_slug(org_name),
            "brand": settings.DEFAULT_BRAND,
            "timezone": timezone("UTC"),
        }
        user = self.user_model.objects.create(**user_data)

        language = self.request.branding.get("language", settings.DEFAULT_LANGUAGE)
        user_settings = user.get_settings()
        user_settings.language = language
        user_settings.save()

        org_data.update({"created_by": user, "modified_by": user})
        org = Org.objects.create(**org_data)
        org.administrators.add(user)
        branding = org.get_branding()
        org.initialize(
            branding=branding, topup_size=branding.get("welcome_topup", 1000)
        )

        return user
