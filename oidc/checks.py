"""
Deployment checks for the oidc app, registered from ``oidcConfig.ready``.
"""

from django.conf import settings
from django.core.checks import Warning as CheckWarning


def check_step_up_demands_fresh_authentication(app_configs=None, **kwargs):
    """A non-zero ``STEP_UP["MAX_AGE"]`` lets the provider skip the prompt.

    :mod:`oidc.stepup` explains why only ``max_age=0`` forces a fresh factor.
    ``redeem_step_up`` catches a replayed session only when the provider
    returns ``auth_time``.
    """
    servers = getattr(settings, "OPENID_CONNECT_AUTH_SERVERS", {}) or {}
    offenders = sorted(
        name
        for name, config in servers.items()
        if ((config or {}).get("STEP_UP") or {}).get("MAX_AGE", 0)
    )
    if not offenders:
        return []
    return [
        CheckWarning(
            "Step-up does not force a fresh authentication for: "
            f"{', '.join(offenders)}. The identity provider may satisfy the "
            "request from the existing session and prompt for nothing, while "
            "still returning the assurance claim.",
            hint="Set STEP_UP['MAX_AGE'] = 0 on these auth servers.",
            id="oidc.W001",
        )
    ]


def check_step_up_grants_use_a_shared_cache(app_configs=None, **kwargs):
    """A local-memory cache is per-process, so a step-up grant or state
    created on one worker is unknown to the next."""
    servers = getattr(settings, "OPENID_CONNECT_AUTH_SERVERS", {}) or {}
    if not any((config or {}).get("STEP_UP") for config in servers.values()):
        return []
    caches = getattr(settings, "CACHES", {}) or {}
    backend = caches.get("default", {}).get("BACKEND", "")
    if "locmem" not in backend.lower():
        return []
    return [
        CheckWarning(
            "Step-up is configured but CACHES['default'] is a local-memory "
            "backend, which is not shared across processes.",
            hint="Use a shared cache (Redis or Memcached) for CACHES['default'].",
            id="oidc.W002",
        )
    ]
