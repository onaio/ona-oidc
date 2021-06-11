"""
oidc Viewsets module
"""
import importlib
from typing import Optional

from django.conf import settings
from django.contrib.auth import get_user_model, login
from django.contrib.auth import logout as logout_backend
from django.http import (
    HttpRequest,
    HttpResponse,
    HttpResponseBadRequest,
    HttpResponseRedirect,
)
from django.utils.translation import ugettext as _

import jwt
from rest_framework import permissions, status, viewsets
from rest_framework.decorators import action
from rest_framework.renderers import JSONRenderer, TemplateHTMLRenderer
from rest_framework.response import Response

import oidc.settings as default
from oidc.client import OpenIDClient
from oidc.client import config as auth_config

default_config = getattr(default, "OPENID_CONNECT_VIEWSET_CONFIG", {})
SSO_COOKIE_NAME = "SSO"


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
        config = getattr(settings, "OPENID_CONNECT_VIEWSET_CONFIG", {})
        self.jwt = config.get("JWT_SECRET_KEY", "")
        self.required_fields = (
            config.get("REQUIRED_USER_CREATION_FIELDS")
            or default_config["REQUIRED_USER_CREATION_FIELDS"]
        )
        self.user_creation_fields = (
            config.get("USER_CREATION_FIELDS") or default_config["USER_CREATION_FIELDS"]
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
        client = self._get_client(**kwargs)
        if client:
            return client.login()
        return HttpResponseBadRequest(
            _("Unable to process OpenID connect login request."),
        )

    @action(methods=["GET"], detail=False)
    def logout(self, request: HttpRequest, **kwargs: dict) -> HttpResponse:
        client = self._get_client(**kwargs)
        if client:
            response = client.logout()

            if self.use_auth_backend:
                logout_backend(request)
            if self.use_sso:
                response.delete_cookie(SSO_COOKIE_NAME)

            return response
        return HttpResponseBadRequest(
            _("Unable to process OpenID connect logout request."),
        )

    def _check_user_exists(self, user_data: dict) -> bool:
        """
        Helper function that checks if a user exists. If user_data does not
        contain the unique user field the assumption is that the user
        exists.
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
        config = getattr(settings, "OPENID_CONNECT_VIEWSET_CONFIG", {})
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
                SSO_COOKIE_NAME,
                value=sso_cookie,
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
            if k in self.map_claim_to_model:
                data[self.map_claim_to_model[k]] = v
            else:
                data[k] = v
        return data

    @action(methods=["POST"], detail=False)
    def callback(self, request: HttpRequest, **kwargs: dict) -> HttpResponse:
        client = self._get_client(**kwargs)
        if client:
            user_data = request.POST.dict()
            id_token = user_data.pop("id_token") if "id_token" in user_data else None
            code = user_data.pop("code") if "code" in user_data else None

            if code and not id_token:
                id_token = client.retrieve_token_using_auth_code(code)

            if id_token:
                user = None

                # Verify, decode and retrieve user information from ID Token
                decoded_token = client.verify_and_decode_id_token(id_token)
                user_data.update(decoded_token)
                user_data = self.map_claims_to_model_field(user_data)
                email = user_data.get("email")

                if self.user_model.objects.filter(email=email).count() > 0:
                    user = self.user_model.objects.get(email=email)
                else:
                    if self._check_user_exists(user_data):
                        # If a user with the unique field exists request the
                        # user to enter unique field
                        field = self.unique_user_filter_field.capitalize()
                        return Response(
                            {
                                "id_token": id_token,
                                "error": _(f"{field} field missing or already in use."),
                            },
                            template_name="oidc/oidc_user_data_entry.html",
                        )

                if not user:
                    missing_fields = set(self.required_fields).difference(
                        set(user_data.keys())
                    )

                    # Use last_name as first_name if first_name is missing
                    if "first_name" in missing_fields and "last_name" in user_data:
                        user_data["first_name"] = user_data["last_name"]
                        missing_fields.remove("first_name")

                    # use email as username if username is missing
                    if "username" in missing_fields and "email" in user_data:
                        user_data["username"] = user_data["email"]
                        missing_fields.remove("username")

                    if len(missing_fields) > 0:
                        missing_fields = ", ".join(missing_fields)
                        return Response(
                            {"error": _(f"Missing required fields: {missing_fields}")},
                            status=status.HTTP_400_BAD_REQUEST,
                            template_name="oidc/oidc_missing_detail.html",
                        )

                    user_data = {
                        k: v
                        for k, v in user_data.items()
                        if k in self.user_creation_fields
                    }
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
