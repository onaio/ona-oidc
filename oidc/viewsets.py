"""
oidc Viewsets module
"""
import importlib
import re
from typing import Optional, Tuple

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
from oidc.client import REDIRECT_AFTER_AUTH, NonceVerificationFailed, OpenIDClient
from oidc.client import config as auth_config
from oidc.utils import str_to_bool

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
        self.user_default_fields = config.get("USER_DEFAULTS") or {}
        self.map_claim_to_model = (
            config.get("MAP_CLAIM_TO_MODEL") or default_config["MAP_CLAIM_TO_MODEL"]
        )
        self.use_sso = str_to_bool(config.get("USE_SSO_COOKIE", True))
        self.sso_cookie = (
            config.get("SSO_COOKIE_DATA") or default_config["SSO_COOKIE_DATA"]
        )
        self.jwt_algorithm = (
            config.get("JWT_ALGORITHM") or default_config["JWT_ALGORITHM"]
        )
        self.split_name_claim = (
            config.get("SPLIT_NAME_CLAIM") or default_config["SPLIT_NAME_CLAIM"]
        )
        self.use_email_as_username = config.get(
            "USE_EMAIL_USERNAME", default_config["USE_EMAIL_USERNAME"]
        )
        self.cookie_max_age = config.get("SSO_COOKIE_MAX_AGE")
        self.cookie_domain = config.get("SSO_COOKIE_DOMAIN", "localhost")
        self.use_auth_backend = str_to_bool(config.get("USE_AUTH_BACKEND", False))
        self.auth_backend = config.get(
            "AUTH_BACKEND", "django.contrib.auth.backends.ModelBackend"
        )
        self.unique_user_filter_field = (
            config.get("USER_UNIQUE_FILTER_FIELD")
            or default_config["USER_UNIQUE_FILTER_FIELD"]
        )
        self.replaceable_username_characters = config.get(
            "REPLACE_USERNAME_CHARACTERS", default_config["REPLACE_USERNAME_CHARACTERS"]
        )
        self.username_char_replacement = config.get(
            "USERNAME_REPLACEMENT_CHARACTER",
            default_config["USERNAME_REPLACEMENT_CHARACTER"],
        )
        self.field_validation_regex = (
            config.get("FIELD_VALIDATION_REGEX")
            or default_config["FIELD_VALIDATION_REGEX"]
        )

    def _get_client(self, auth_server: str) -> Optional[OpenIDClient]:
        if auth_server in auth_config:
            return OpenIDClient(auth_server)
        return None

    @action(methods=["GET"], detail=False)
    def login(self, request: HttpRequest, **kwargs: dict) -> HttpResponse:
        client = self._get_client(**kwargs)
        if client:
            return client.login(redirect_after=request.query_params.get("next"))
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
                response.delete_cookie(SSO_COOKIE_NAME, domain=self.cookie_domain)

            return response
        return HttpResponseBadRequest(
            _("Unable to process OpenID connect logout request."),
        )

    def _check_user_uniqueness(self, user_data: dict) -> bool:
        """
        Helper function that checks if the supplied user data is unique. If user_data does not
        contain the unique user field the assumption is that the user
        exists.
        """
        if user_data.get(self.unique_user_filter_field):
            unique_field_value = user_data.get(self.unique_user_filter_field)
            unique_field = self.unique_user_filter_field + "__iexact"
            filter_kwargs = {unique_field: unique_field_value}
            return not self.user_model.objects.filter(**filter_kwargs).count() > 0
        return False

    def generate_successful_response(
        self, request, user, redirect_after=None
    ) -> HttpResponse:
        """
        Generates a success response for a successful Open ID Connect
        Authentication request
        """
        config = getattr(settings, "OPENID_CONNECT_VIEWSET_CONFIG", {})
        response = HttpResponseRedirect(
            redirect_after or config.get("REDIRECT_AFTER_AUTH")
        )

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

        # Split the name claim into `first_name` & `last_name`
        if (self.split_name_claim and "name" in user_data.keys()) and (
            "first_name" not in data.keys() or "last_name" not in data.keys()
        ):
            split_name = user_data["name"].split(" ")
            data["first_name"] = " ".join(split_name[:1])
            data["last_name"] = " ".join(split_name[1:])
        return data

    def validate_fields(self, data: dict) -> dict:
        for k, v in data.items():
            if k in self.field_validation_regex:
                field_validation_regex = self.field_validation_regex[k]
                regex = re.compile(field_validation_regex.get("regex"))
                if regex and not regex.search(data[k]):
                    raise ValueError(
                        field_validation_regex.get("help_text")
                        or f"Invalid `{k}` value `{data[k]}`"
                    )

    def _get_user_group_defaults(self, email: str) -> dict:
        groups = [key for key in self.user_default_fields.keys() if key != "default"]

        user_default = self.user_default_fields.get("default", {})
        for group in groups:
            match = re.match(group, email)
            if match:
                user_default = self.user_default_fields[group]
                break

        return user_default

    def _clean_user_data(self, user_data) -> Tuple[dict, Optional[list]]:
        user_data = {
            k: v for k, v in user_data.items() if k in self.user_creation_fields
        }
        missing_fields = set(self.required_fields).difference(set(user_data.keys()))

        # Use last_name as first_name if first_name is missing
        if "first_name" in missing_fields and "last_name" in user_data:
            user_data["first_name"] = user_data["last_name"]
            missing_fields.remove("first_name")

        # use email as username if username is missing
        if self.use_email_as_username:
            if "username" in missing_fields and "email" in user_data:
                username = user_data["email"].split("@")[0]
                if (
                    self.user_model.objects.filter(username__iexact=username).count()
                    == 0
                ):
                    username = user_data["email"].split("@")[0]
                    if (
                        self.replaceable_username_characters
                        and self.username_char_replacement
                    ):
                        for char in list(self.replaceable_username_characters):
                            username = username.replace(
                                char, self.username_char_replacement
                            )

                    # Validate retrieved username matches regex
                    if "username" in self.field_validation_regex:
                        regex = re.compile(
                            self.field_validation_regex["username"].get("regex")
                        )
                        if regex.search(username):
                            user_data["username"] = username
                            missing_fields.remove("username")

        return user_data, missing_fields

    @action(methods=["POST"], detail=False)
    def callback(self, request: HttpRequest, **kwargs: dict) -> HttpResponse:
        client = self._get_client(**kwargs)
        user = None
        redirect_after = None
        error = None
        if client:
            user_data = request.POST.dict()
            id_token = user_data.get("id_token")

            if not id_token and user_data.get("code"):
                id_token, error = client.retrieve_token_using_auth_code(user_data.get("code"))

            if id_token:
                try:
                    decoded_token = client.verify_and_decode_id_token(id_token)
                    if decoded_token.get(REDIRECT_AFTER_AUTH):
                        redirect_after = decoded_token.pop(REDIRECT_AFTER_AUTH)
                    user_data.update(decoded_token)
                    user_data = self.map_claims_to_model_field(user_data)
                    filter_kwargs = None

                    if "email" in user_data:
                        filter_kwargs = {"email": user_data.get("email")}
                    elif "emails" in user_data:
                        user_data["email"] = user_data.get("emails")[0]
                        filter_kwargs = {"email__in": user_data.get("emails")}

                    if (
                        filter_kwargs
                        and self.user_model.objects.filter(**filter_kwargs).count() > 0
                    ):
                        user = self.user_model.objects.get(**filter_kwargs)

                    if not user:
                        user_data, missing_fields = self._clean_user_data(user_data)
                        if missing_fields:
                            if (
                                len(missing_fields) == 1
                                and list(missing_fields)[0] == "username"
                            ):
                                data = {"id_token": id_token}
                                return Response(
                                    data, template_name="oidc/oidc_user_data_entry.html"
                                )
                            else:
                                missing_fields = ", ".join(missing_fields)
                                return Response(
                                    {
                                        "error": _(
                                            f"Missing required fields: {missing_fields}"
                                        ),
                                        "error_title": _("Missing details in ID Token"),
                                    },
                                    status=status.HTTP_400_BAD_REQUEST,
                                    template_name="oidc/oidc_unrecoverable_error.html",
                                )
                        elif not self._check_user_uniqueness(user_data):
                            data = {
                                "id_token": id_token,
                                "error": f"{self.unique_user_filter_field.capitalize()} field is already in use.",
                            }
                            return Response(
                                data, template_name="oidc/oidc_user_data_entry.html"
                            )

                        self.validate_fields(user_data)

                        create_data = self._get_user_group_defaults(
                            user_data.get("email")
                        )
                        create_data.update(user_data)

                        user = self.create_login_user(create_data)
                except ValueError as e:
                    return Response(
                        {"error": str(e)},
                        status=status.HTTP_400_BAD_REQUEST,
                        template_name="oidc/oidc_user_data_entry.html",
                    )
                except NonceVerificationFailed:
                    return Response(
                        {
                            "error": _(
                                "Unable to validate authentication request; Nonce verification has failed. Kindly retry authentication process."
                            ),
                            "error_title": _(
                                "Authentication request verification failed"
                            ),
                        },
                        status=status.HTTP_401_UNAUTHORIZED,
                        template_name="oidc/oidc_unrecoverable_error.html",
                    )
                else:
                    if user:
                        return self.generate_successful_response(
                            request, user, redirect_after=redirect_after
                        )
        return HttpResponseBadRequest(
                _(f"Unable to process OpenID connect authentication request: {kwargs}. Retrieve ID Token error: {error}"),
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
