"""
oidc Viewsets module
"""

import importlib
import logging
import re
import traceback
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
from django.utils import timezone
from django.utils.translation import gettext as _

import jwt
from rest_framework import permissions, status, viewsets
from rest_framework.decorators import action
from rest_framework.renderers import JSONRenderer, TemplateHTMLRenderer
from rest_framework.response import Response
from rest_framework.reverse import reverse

import oidc.settings as default
from oidc.client import (
    REDIRECT_AFTER_AUTH,
    NoJSONWebKeyFound,
    NonceVerificationFailed,
    OpenIDClient,
    TokenVerificationFailed,
)
from oidc.utils import str_to_bool

default_config = getattr(default, "OPENID_CONNECT_VIEWSET_CONFIG", {})
SSO_COOKIE_NAME = "SSO"

logger = logging.getLogger(__name__)


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
        self.unique_user_filter_fields = (
            config.get("USER_UNIQUE_FILTER_FIELDS")
            or default_config["USER_UNIQUE_FILTER_FIELDS"]
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
        auth_config = getattr(settings, "OPENID_CONNECT_AUTH_SERVERS", {})

        if auth_server in auth_config:
            return OpenIDClient(auth_server)
        return None

    @action(methods=["GET"], detail=False)
    def login(self, request: HttpRequest, **kwargs: dict) -> HttpResponse:
        client = self._get_client(auth_server=kwargs.get("auth_server"))
        if client:
            response = client.login(redirect_after=request.query_params.get("next"))
            # Add Clear-Site-Data headers
            response["Clear-Site-Data"] = '"cache", "cookies"'
            return response
        return HttpResponseBadRequest(
            _("Unable to process OpenID connect login request."),
        )

    @action(methods=["GET"], detail=False)
    def logout(self, request: HttpRequest, **kwargs: dict) -> HttpResponse:
        client = self._get_client(auth_server=kwargs.get("auth_server"))
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

    def _check_user_uniqueness(self, user_data: dict) -> Optional[str]:
        """
        Helper function that checks if the supplied user data is unique. If user_data does not
        contain the unique user field the assumption is that the user
        exists.
        """
        for user_field in self.unique_user_filter_fields:
            if user_data.get(user_field):
                unique_field_value = user_data.get(user_field)
                unique_field = user_field + "__iexact"
                filter_kwargs = {unique_field: unique_field_value}
                if self.user_model.objects.filter(**filter_kwargs).count() > 0:
                    return user_field
        return None

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
                    logger.info(f"Invalid `{k}` value `{data[k]}`")
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

        # use email as username if username is missing or username is invalid
        if self.use_email_as_username:
            username_regex = re.compile(
                self.field_validation_regex["username"].get("regex")
            )
            if (
                "username" in missing_fields
                or not username_regex.search(user_data["username"])
            ) and "email" in user_data:
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
                if "username" in self.field_validation_regex and username_regex.search(
                    username
                ):
                    user_data["username"] = username
                    if "username" in missing_fields:
                        missing_fields.remove("username")

        return user_data, missing_fields

    @action(methods=["POST"], detail=False)
    def callback(self, request: HttpRequest, **kwargs: dict) -> HttpResponse:  # noqa
        client = self._get_client(auth_server=kwargs.get("auth_server"))
        user = None
        redirect_after = None
        if client:
            user_data = request.POST.dict()
            id_token = user_data.get("id_token")
            provided_username = user_data.get("username")

            if not id_token and user_data.get("code"):
                try:
                    id_token = client.retrieve_token_using_auth_code(
                        user_data.get("code")
                    )
                except TokenVerificationFailed as e:
                    return Response(
                        {
                            "error": _(
                                f"Unable to retrieve ID Token; {e}. Kindly retry authentication process."
                            ),
                            "error_title": _(
                                "Authentication request verification failed"
                            ),
                        },
                        status=status.HTTP_401_UNAUTHORIZED,
                        template_name="oidc/oidc_unrecoverable_error.html",
                    )

            if id_token:
                try:
                    decoded_token = client.verify_and_decode_id_token(id_token)
                    if decoded_token.get(REDIRECT_AFTER_AUTH):
                        redirect_after = decoded_token.pop(REDIRECT_AFTER_AUTH)
                    user_data.update(decoded_token)
                    user_data = self.map_claims_to_model_field(user_data)
                    if provided_username:
                        user_data.update({"username": provided_username})
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
                                logger.info("missing_fields: ", missing_fields)
                                return Response(
                                    data, template_name="oidc/oidc_user_data_entry.html"
                                )
                            else:
                                missing_fields = ", ".join(missing_fields)
                                logger.error(f"missing fields: {missing_fields}")
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
                        else:
                            field = self._check_user_uniqueness(user_data)
                            if field:
                                data = {
                                    "id_token": id_token,
                                    "error": f"{field.capitalize()} field is already in use.",
                                }
                                logger.info(data)
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
                    stack_trace = traceback.format_exc()
                    logger.info("ValueError")
                    logger.info(stack_trace)
                    return Response(
                        {"error": str(e), "id_token": id_token},
                        status=status.HTTP_400_BAD_REQUEST,
                        template_name="oidc/oidc_user_data_entry.html",
                    )
                except jwt.exceptions.DecodeError:
                    return Response(
                        {
                            "error": _("Failed to decode ID Token."),
                            "error_title": _("Invalid ID Token"),
                        },
                        status=status.HTTP_401_UNAUTHORIZED,
                        template_name="oidc/oidc_unrecoverable_error.html",
                    )
                except (NonceVerificationFailed, NoJSONWebKeyFound) as e:
                    return Response(
                        {
                            "error": _(
                                f"Unable to validate authentication request; {e}. Kindly retry authentication process."
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
                        user.last_login = timezone.now()
                        user.save(update_fields=["last_login"])
                        return self.generate_successful_response(
                            request, user, redirect_after=redirect_after
                        )
        auth_servers = list(settings.OPENID_CONNECT_AUTH_SERVERS.keys())
        default_auth_server = auth_servers[0] if auth_servers else "default"
        return Response(
            {
                "error": _("Unable to process OpenID connect authentication request."),
                "error_title": _(
                    "Unable to process OpenID connect authentication request."
                ),
                "login_url": reverse(
                    "openid_connect_login", kwargs={"auth_server": default_auth_server}
                ),
            },
            status=status.HTTP_400_BAD_REQUEST,
            template_name="oidc/oidc_unrecoverable_error.html",
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
        org_name = user_data.pop("username")
        user_data["username"] = user_data.get("email")

        org_data = {
            "name": org_name,
            "slug": Org.get_unique_slug(org_name),
            "brand": settings.DEFAULT_BRAND,
            "timezone": f"{timezone.utc}",
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
