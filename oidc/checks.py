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


#: View kwargs an override has to carry forward. Dropping ``permission_classes``
#: falls back to the viewset default -- ``AllowAny`` -- which on an
#: account-proxy route silently removes the CSRF/Origin gate, and the route
#: still looks identical by path, name and verb. Compared as subsets so a
#: subclass may add to them.
_GUARDED_VIEW_KWARGS = (
    "permission_classes",
    "authentication_classes",
    "renderer_classes",
)


def _kwarg_survives(inherited, current, key: str) -> bool:
    return set(getattr(inherited, "kwargs", {}).get(key) or ()) <= set(
        getattr(current, "kwargs", {}).get(key) or ()
    )


def _hint_kwargs(inherited) -> str:
    """The guarded view kwargs, spelled out so the hint can be copied."""
    declared = [
        f"{key}={[c.__name__ for c in getattr(inherited, 'kwargs', {})[key]]}"
        for key in _GUARDED_VIEW_KWARGS
        if key in getattr(inherited, "kwargs", {})
    ]
    return ", ".join(declared) if declared else "its view kwargs"


def _routes_match(inherited, current) -> bool:
    """Whether an override still produces the route its parent declared.

    Name equality is not enough: a re-declared decorator with a different
    ``url_path`` moves the endpoint, ``detail=True`` moves it again by
    adding a ``pk`` segment, a different ``url_name`` breaks ``reverse()``,
    a fresh ``MethodMapper`` silently drops any ``@<action>.mapping.<verb>``
    companion the parent had, and omitted view kwargs quietly widen who may
    call it.

    The mapping is compared by verb rather than by (verb, handler name): the
    route carries the verbs, so renaming the method a companion points at is
    a rename, not a lost route.
    """
    return (
        getattr(inherited, "url_path", None) == getattr(current, "url_path", None)
        and getattr(inherited, "url_name", None) == getattr(current, "url_name", None)
        and getattr(inherited, "detail", None) == getattr(current, "detail", None)
        and inherited.mapping.keys() <= current.mapping.keys()
        and all(
            _kwarg_survives(inherited, current, key) for key in _GUARDED_VIEW_KWARGS
        )
    )


def check_actions_survive_subclassing(app_configs, **kwargs):
    """Catch a subclass that overrode an ``@action`` without re-declaring it.

    The router builds routes from the ``@action`` metadata attached to the
    function. A plain override replaces the function and drops that
    metadata, so the route is never generated -- the endpoint 404s with
    nothing to indicate why. Silent, and only reachable through
    ``VIEWSET_CLASS``, so it belongs at deploy time.
    """
    from oidc.urls import get_viewset_class

    try:
        viewset_class = get_viewset_class()
    except Exception:  # pragma: no cover - a broken VIEWSET_CLASS is its own error
        return []

    routed = {action.__name__: action for action in viewset_class.get_extra_actions()}
    errors = []
    for klass in viewset_class.__mro__[1:]:
        for name, inherited in vars(klass).items():
            if not hasattr(inherited, "mapping"):
                continue
            current = routed.get(name)
            if current is not None and _routes_match(inherited, current):
                continue
            errors.append(
                Error(
                    f"{viewset_class.__name__}.{name}() overrides the @action "
                    f"declared on {klass.__name__} without preserving its "
                    f"route.",
                    hint=(
                        f"Re-apply the decorator on the override, matching "
                        f"{klass.__name__}.{name} exactly: url_path="
                        f"{getattr(inherited, 'url_path', None)!r}, url_name="
                        f"{getattr(inherited, 'url_name', None)!r}, detail="
                        f"{getattr(inherited, 'detail', None)!r}, at least the "
                        f"methods {sorted(inherited.mapping)}, and "
                        f"{_hint_kwargs(inherited)}. Any @{name}.mapping.<verb> "
                        f"companions must be re-declared too -- a fresh "
                        f"decorator replaces them."
                    ),
                    id="oidc.E002",
                )
            )
            routed[name] = inherited  # don't report the same name twice
    return errors
