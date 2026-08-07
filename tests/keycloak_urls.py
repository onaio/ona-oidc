"""
URLconf for a deployment that opts into the Keycloak account proxy.

``oidc.urls`` resolves ``VIEWSET_CLASS`` at import time, so routing tests for
the mixin need their own URLconf rather than ``override_settings``.
"""

from oidc.keycloak import KeycloakOpenIDConnectViewset
from oidc.routers import UnprefixedNameRouter

router = UnprefixedNameRouter(trailing_slash=False)
router.register(
    r"oidc/(?P<auth_server>\w+)", KeycloakOpenIDConnectViewset, basename="oidc"
)

urlpatterns = router.urls
