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
        from oidc.checks import (
            check_step_up_demands_fresh_authentication,
            check_step_up_grants_use_a_shared_cache,
        )

        register(check_step_up_demands_fresh_authentication)
        register(check_step_up_grants_use_a_shared_cache)
