"""
Routers used to build this package's URLs.
"""

from rest_framework.routers import DynamicRoute, SimpleRouter


class UnprefixedNameRouter(SimpleRouter):
    """A router that publishes only ``@action`` routes, named ``{url_name}``.

    ``reverse("oidc:openid_connect_login")`` is public, so the names keep no
    ``{basename}-`` prefix. The list and detail routes are left out: a
    ``VIEWSET_CLASS`` helper that happens to be called ``update`` or ``list``
    must not become an endpoint.
    """

    routes = [
        route._replace(name=route.name.replace("{basename}-", ""))
        for route in SimpleRouter.routes
        if isinstance(route, DynamicRoute)
    ]
