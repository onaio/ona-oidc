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
        # Imported here rather than at module scope: the check pulls in the
        # viewsets, which read settings, and that must not happen while the
        # app registry is still populating.
        from oidc.checks import (
            check_actions_survive_subclassing,
            check_session_backend_can_hold_tokens,
        )

        register(check_session_backend_can_hold_tokens, "security")
        register(check_actions_survive_subclassing)
