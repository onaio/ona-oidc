"""
Application Module for oidc app
"""

from django.apps import AppConfig
from django.core.checks import register
from django.utils.translation import gettext_lazy as _


class oidcConfig(AppConfig):
    """
    oidc Config Class
    """

    name = "oidc"
    app_label = "oidc"
    verbose_name = _("OpenID Connect")

    def ready(self):
        # Imported here rather than at module scope: the check reads settings,
        # and that must not happen while the app registry is still populating.
        from oidc.checks import check_step_up_demands_fresh_authentication

        # Registered by the package, so a consumer gets it without having to
        # know this package's config has a footgun in it.
        register(check_step_up_demands_fresh_authentication)
