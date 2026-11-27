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
        Register the security checks, and fail at startup when browser
        binding is enforced on a cache that cannot store login bindings.
        """
        from oidc.checks import (
            check_request_mode,
            check_step_up_configuration,
            check_step_up_demands_fresh_authentication,
            check_step_up_grants_use_a_shared_cache,
        )
        from oidc.client import check_login_binding_cache

        register(check_request_mode, Tags.security)
        register(check_step_up_configuration, Tags.security)
        register(check_step_up_demands_fresh_authentication, Tags.security)
        register(check_step_up_grants_use_a_shared_cache, Tags.security)
        check_login_binding_cache()
