"""
Application Module for oidc app
"""

from django.apps import AppConfig
from django.core.checks import Tags, register
from django.utils.translation import gettext_lazy as _


class oidcConfig(AppConfig):
    """
    oidc Config Class
    """

    name = "oidc"
    app_label = "oidc"
    verbose_name = _("OpenID Connect")

    def ready(self):
        from oidc.checks import check_request_mode

        register(check_request_mode, Tags.security)
