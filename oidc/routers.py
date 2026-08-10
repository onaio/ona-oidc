"""
Routers used to build this package's URLs.
"""

from rest_framework.routers import DynamicRoute, SimpleRouter


class UnprefixedNameRouter(SimpleRouter):
    """A router that names ``@action`` routes ``{url_name}``, not
    ``{basename}-{url_name}``.

    ``reverse("oidc:openid_connect_login")`` is part of this package's public
    surface — used by the unrecoverable-error template and by consumers — so
    the names the hand-written URLconf declared have to survive. A stock
    router would rename that route to ``oidc-openid_connect_login``.

    Only the dynamic routes: every name this package publishes comes from an
    ``@action``, while ``{basename}-list``/``-detail`` belong to DRF's own
    conventions. Stripping those too would rename a ``VIEWSET_CLASS`` with
    CRUD methods to a bare ``list``/``detail``, which collides across
    routers and breaks hyperlinked serializers reversing ``<model>-detail``.
    """

    routes = [
        (
            route._replace(name=route.name.replace("{basename}-", ""))
            if isinstance(route, DynamicRoute)
            else route
        )
        for route in SimpleRouter.routes
    ]
