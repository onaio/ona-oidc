"""
System checks for the oidc app
"""

from collections.abc import Mapping

from django.conf import settings
from django.core.checks import Tags, Warning, register


@register(Tags.security)
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
            id="oidc.W001",
        )
        for name, server in servers.items()
        if isinstance(server, Mapping) and server.get("REQUEST_MODE") == "query"
    ]
