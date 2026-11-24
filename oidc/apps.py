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
        """
        Register the request-mode check, and fail at startup when
        browser binding is enforced on a cache that cannot store login
        bindings.
        """
        from oidc.checks import check_request_mode
        from oidc.client import check_login_binding_cache

        register(check_request_mode, Tags.security)
        check_login_binding_cache()
