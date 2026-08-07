"""
URL Configuration file for ona-oidc
"""

from django.conf import settings
from django.utils.module_loading import import_string

from rest_framework.routers import SimpleRouter

from oidc.utils import str_to_bool
from oidc.viewsets import RapidProOpenIDConnectViewset, UserModelOpenIDConnectViewset

app_name = "oidc"


def get_viewset_class():
    """The viewset these URLs route to.

    ``VIEWSET_CLASS`` (a dotted path) lets a deployment route to its own
    subclass while still using ``include("oidc.urls")``. Without it, changing
    this one name means copying the whole URLconf, and then mirroring every
    route by hand, forever.

    ``USE_RAPIDPRO_VIEWSET`` is the older boolean form and still works.
    """
    config = getattr(settings, "OPENID_CONNECT_VIEWSET_CONFIG", {})
    dotted_path = config.get("VIEWSET_CLASS")
    if dotted_path:
        return import_string(dotted_path)
    if str_to_bool(config.get("USE_RAPIDPRO_VIEWSET", False)):
        return RapidProOpenIDConnectViewset
    return UserModelOpenIDConnectViewset


viewset_class = get_viewset_class()

# Routes are generated from the @action decorators on the viewset, so each
# action carries its own url_path, url_name and view kwargs -- including the
# account-proxy CSRF gate, which previously had to be repeated per route here
# and mirrored by every consumer that declared its own URLconf.
#
# trailing_slash=False keeps the existing paths (/oidc/<server>/login, not
# /login/). The auth_server capture lives in the prefix; SimpleRouter
# interpolates it into every generated pattern.
router = SimpleRouter(trailing_slash=False)
router.register(r"oidc/(?P<auth_server>\w+)", viewset_class, basename="oidc")

urlpatterns = router.urls
