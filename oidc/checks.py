"""
Deployment checks for the oidc app.

Registered from ``oidcConfig.ready``, so they run on ``manage.py check``,
``migrate``, ``runserver`` and any other management command -- i.e. at
deploy time rather than on the first user who tries to sign in.
"""

from django.conf import settings
from django.core.checks import Error

_COOKIE_BACKEND = "django.contrib.sessions.backends.signed_cookies"


def check_session_backend_can_hold_tokens(app_configs, **kwargs):
    """Refuse to keep OIDC tokens in a client-readable session.

    Signed-cookie sessions are signed but not encrypted: the contents ride
    in a cookie the browser can read, and stay replayable after logout
    because there is no server-side record to delete. That is tolerable for
    the id_token alone -- the browser already holds it -- but not for the
    access and refresh tokens a proxy-enabled viewset stores.

    ``BaseOpenIDConnectViewset.__init__`` also refuses this, but a viewset
    is only instantiated per request, so on its own that surfaces as a 500
    for the first user to sign in. This runs at deploy time instead.
    """
    if getattr(settings, "SESSION_ENGINE", "") != _COOKIE_BACKEND:
        return []

    # Imported lazily: this module is imported from ``ready()``, and
    # ``oidc.urls`` pulls in the viewsets, which read settings at import.
    from oidc.urls import get_viewset_class

    try:
        viewset_class = get_viewset_class()
    except Exception:  # pragma: no cover - a broken VIEWSET_CLASS is its own error
        return []

    if not getattr(viewset_class, "stash_oidc_tokens", False):
        return []

    return [
        Error(
            "SESSION_ENGINE is the signed_cookies backend, but "
            f"{viewset_class.__name__} stores OIDC access and refresh tokens "
            "in request.session.",
            hint=(
                "Cookie-based sessions are signed but not encrypted, so the "
                "tokens would be readable by the client and replayable after "
                "logout. Use a server-side SESSION_ENGINE (db, cache, "
                "cached_db or file), or route to a viewset that does not mix "
                "in KeycloakAccountMixin."
            ),
            id="oidc.E001",
        )
    ]
