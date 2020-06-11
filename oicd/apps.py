"""
Application Module for oicd app
"""
from django.apps import AppConfig
from django.utils.translation import ugettext_lazy as _


class OICDConfig(AppConfig):
    """
    OICD Config Class
    """

    name = "oicd"
    app_label = "oicd"
    verbose_name = _("OpenID Connect")
