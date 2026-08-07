"""
Cross-origin protection for the cookie-identified Keycloak Account REST proxy.

The proxy actions take the caller's identity from the OIDC tokens stashed in
``request.session`` (a cookie), and run with ``authentication_classes=[]`` —
so DRF's ``SessionAuthentication`` CSRF check does not apply. Two in-code
checks stand in for it, so the boundary holds whatever the deployment's CORS
config says:

  * Every method enforces the ``Origin`` allowlist (the trusted first-party
    SPA hosts; a missing ``Origin`` — same-origin requests may omit it — is
    allowed). For *writes* this rejects a cross-origin page that sets the
    custom header via ``fetch``. For *reads* it is what closes the leak: the
    only way a cross-origin page can read one of these listings is a
    credentialed CORS ``fetch`` against a deployment whose CORS reflects
    arbitrary origins, and that fetch always carries ``Origin`` — so it is
    refused here, server-side, before Keycloak is ever called.
  * Unsafe methods additionally require a custom header that cross-site
    markup (``<form>``, ``<img>``, navigation) cannot set — so markup can't
    forge writes at all. Reads deliberately do *not* require it: markup GETs
    cannot read a JSON response in any current browser, so a header check on
    reads adds nothing the ``Origin`` check does not, and the SPA sends the
    header only on writes.

Neither check depends on the session cookie's ``SameSite`` attribute (kept
as ``Lax`` + ``Secure`` as an additional layer), so the protection holds
even when a cross-site SPA forces ``SameSite=None`` to send credentials.
Keeping the account host out of any permissive ``CORS_ALLOW_ALL_ORIGINS`` /
regex allowlist remains good hygiene, but is no longer load-bearing.
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
            f"Account requests must come from a trusted origin; state-changing "
            f"ones must also include the {get_account_request_header()} header."
        )

    def has_permission(self, request, view):
        if not is_allowed_account_origin(view.kwargs.get("auth_server"), request):
            return False
        if request.method in SAFE_METHODS:
            return True
        return bool(request.headers.get(get_account_request_header()))
