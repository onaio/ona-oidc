"""
CSRF protection for the cookie-identified Keycloak Account REST proxy.

The proxy actions take the caller's identity from the OIDC tokens stashed in
``request.session`` (a cookie), and run with ``authentication_classes=[]`` —
so DRF's ``SessionAuthentication`` CSRF check does not apply. To keep the
state-changing actions from being driven cross-site with the victim's ambient
cookie, unsafe methods must carry a custom request header.

Two in-code checks, so the boundary doesn't hinge on external CORS config:
  * A custom header that cross-site markup (``<form>``, ``<img>``,
    navigation) cannot set — so it can't forge these calls at all.
  * An ``Origin`` allowlist (the trusted first-party SPA hosts) — so a
    cross-origin page that *does* set the header via ``fetch`` is still
    rejected server-side, regardless of how the deployment's CORS is set up.

Neither depends on the session cookie's ``SameSite`` attribute (kept as
``Lax`` + ``Secure`` as an additional layer), so the protection holds even
when a cross-site SPA forces ``SameSite=None`` to send credentials.
"""

from rest_framework.permissions import BasePermission

from oidc.utils import is_allowed_account_origin

#: Header the SPA sets on every state-changing account-proxy request.
ACCOUNT_REQUEST_HEADER = "X-Ona-Account-Request"

_SAFE_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})


class RequireAccountRequestHeader(BasePermission):
    message = (
        f"State-changing account requests must include the "
        f"{ACCOUNT_REQUEST_HEADER} header and come from a trusted origin."
    )

    def has_permission(self, request, view):
        if request.method in _SAFE_METHODS:
            return True
        if not request.headers.get(ACCOUNT_REQUEST_HEADER):
            return False
        return is_allowed_account_origin(
            request.headers.get("Origin"),
            view.kwargs.get("auth_server"),
            request,
        )
