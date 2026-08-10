"""
URL Configuration file for ona-oidc
"""

from django.conf import settings
from django.utils.module_loading import import_string

from oidc.routers import UnprefixedNameRouter
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


# Every route's url_path, url_name and view kwargs — including the
# account-proxy CSRF gate — come from the @action decorators.
# trailing_slash=False keeps paths as /oidc/<server>/login rather than
# /login/; each action opts back into an optional trailing slash itself.
router = UnprefixedNameRouter(trailing_slash=False)
router.register(r"oidc/(?P<auth_server>\w+)", get_viewset_class(), basename="oidc")

urlpatterns = router.urls
