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

    def ready(self):
        """
        Setup ona-oicd default settings
        """
        from django.conf import settings
        import oicd.settings as defaults

        for name in dir(defaults):
            if name.isupper() and not hasattr(settings, name):
                setattr(settings, name, getattr(defaults, name))
