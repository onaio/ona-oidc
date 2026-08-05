"""
CSRF protection for the cookie-identified Keycloak Account REST proxy.

The proxy actions take the caller's identity from the OIDC tokens stashed in
``request.session`` (a cookie), and run with ``authentication_classes=[]`` —
so DRF's ``SessionAuthentication`` CSRF check does not apply. Unsafe methods
are instead gated on two in-code checks, so the boundary doesn't hinge on
external CORS config:
  * A custom header that cross-site markup (``<form>``, ``<img>``,
    navigation) cannot set — so it can't forge these calls at all.
  * An ``Origin`` allowlist (the trusted first-party SPA hosts) — so a
    cross-origin page that *does* set the header via ``fetch`` is still
    rejected server-side, regardless of how the deployment's CORS is set up.

Neither depends on the session cookie's ``SameSite`` attribute (kept as
``Lax`` + ``Secure`` as an additional layer), so the protection holds even
when a cross-site SPA forces ``SameSite=None`` to send credentials.
"""

from rest_framework.permissions import SAFE_METHODS, BasePermission

import oidc.settings as default
from oidc.utils import get_viewset_config, is_allowed_account_origin

_default_config = getattr(default, "OPENID_CONNECT_VIEWSET_CONFIG", {})


def get_account_request_header() -> str:
    """The header the SPA must send on state-changing account-proxy requests.

    Configurable via ``OPENID_CONNECT_VIEWSET_CONFIG["ACCOUNT_REQUEST_HEADER"]``
    so deployments outside Ona are not stuck advertising an ``X-Ona-`` header.
    Any value works as a CSRF defence: what matters is that cross-site markup
    cannot set a custom header at all, not which name is used.
    """
    return get_viewset_config().get(
        "ACCOUNT_REQUEST_HEADER", _default_config["ACCOUNT_REQUEST_HEADER"]
    )


class IsCsrfSafeAccountRequest(BasePermission):
    @property
    def message(self):
        # Resolved per request, not at import: a class-level f-string would
        # freeze the default and keep naming X-Ona-Account-Request after a
        # deployment configured something else.
        return (
            f"State-changing account requests must include the "
            f"{get_account_request_header()} header and come from a trusted origin."
        )

    def has_permission(self, request, view):
        if request.method in SAFE_METHODS:
            return True
        if not request.headers.get(get_account_request_header()):
            return False
        return is_allowed_account_origin(view.kwargs.get("auth_server"), request)
