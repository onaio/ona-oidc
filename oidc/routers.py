"""
Routers used to build this package's URLs.
"""

from rest_framework.routers import SimpleRouter


class UnprefixedNameRouter(SimpleRouter):
    """A router that names routes ``{url_name}``, not ``{basename}-{url_name}``.

    ``reverse("oidc:openid_connect_login")`` is part of this package's public
    surface — used by the unrecoverable-error template and by consumers — so
    the names the hand-written URLconf declared have to survive. A stock
    router would rename that route to ``oidc-openid_connect_login``.
    """

    routes = [
        route._replace(name=route.name.replace("{basename}-", ""))
        for route in SimpleRouter.routes
    ]
