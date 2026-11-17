"""
System checks for the oidc app
"""

from collections.abc import Mapping

from django.conf import settings
from django.core.checks import Warning


def check_request_mode(app_configs, **kwargs):
    """Warn for each auth server that sends credentials in the token URL"""
    servers = getattr(settings, "OPENID_CONNECT_AUTH_SERVERS", None)
    if not isinstance(servers, Mapping):
        return []
    return [
        Warning(
            f"Auth server {name!r} sends client credentials in the token "
            "request URL (REQUEST_MODE 'query').",
            hint=(
                "Proxy and provider access logs keep URLs. Set REQUEST_MODE to "
                "'form_post' unless the provider only accepts query parameters."
            ),
            id="oidc.W003",
        )
        for name, server in servers.items()
        if server.get("REQUEST_MODE") == "query"
    ]
