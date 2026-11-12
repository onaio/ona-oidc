"""
System checks for the oidc app
"""

from django.conf import settings
from django.core.checks import Tags, Warning, register


@register(Tags.security)
def check_request_mode(app_configs, **kwargs):
    servers = getattr(settings, "OPENID_CONNECT_AUTH_SERVERS", {})
    return [
        Warning(
            f"Auth server {name!r} sends client credentials in the token "
            "request URL (REQUEST_MODE 'query').",
            hint=(
                "Proxy and provider access logs keep URLs. Set REQUEST_MODE to "
                "'form_post' unless the provider only accepts query parameters. "
                "Query mode is deprecated."
            ),
            id="oidc.W001",
        )
        for name, server in servers.items()
        if server.get("REQUEST_MODE") == "query"
    ]
