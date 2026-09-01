"""
Deployment checks for the oidc app.

Registered from ``oidcConfig.ready``, so they run on ``manage.py check``,
``migrate``, ``runserver`` and any other management command -- i.e. at deploy
time rather than on the first user who tries to sign in.
"""

from django.conf import settings
from django.core.checks import Warning as CheckWarning


def check_step_up_demands_fresh_authentication(app_configs=None, **kwargs):
    """A non-zero ``STEP_UP["MAX_AGE"]`` is a silent downgrade.

    Measured against Keycloak 26: once a session has reached the required
    level, every later authorization request for that level returns the
    assurance claim with the ORIGINAL ``auth_time`` and prompts the user for
    nothing. The claim then says only "this session once stepped up", which is
    not the question a step-up asks.

    ``auth_time`` is not a sufficient backstop on its own -- the replay carries
    an ``auth_time`` that is genuinely recent, so anything inside
    ``MAX_AUTH_AGE_SECONDS`` passes. Only ``max_age=0`` forces the factor.
    """
    servers = getattr(settings, "OPENID_CONNECT_AUTH_SERVERS", {}) or {}
    offenders = sorted(
        name
        for name, config in servers.items()
        if (config.get("STEP_UP") or {}).get("MAX_AGE", 0)
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
    """A local-memory cache silently voids a grant's single-use TTL.

    ``spend_grant`` treats ``cache.delete``'s return as the single-use check and
    the grant's TTL as its "worthless if left behind" window. ``LocMemCache``
    evaluates expiry only on read, so it reports an expired grant as
    successfully spent -- the TTL does not hold -- and it is per-process, so a
    grant minted on one worker is unknown to the next. Step-up needs a shared
    backend that expires keys on delete (Redis, Memcached).
    """
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
            "backend: it does not enforce a grant's single-use TTL and is not "
            "shared across processes.",
            hint="Use a shared cache that expires keys on delete (Redis or "
            "Memcached) for CACHES['default'].",
            id="oidc.W002",
        )
    ]
