"""
System checks for the oidc app
"""

from collections.abc import Iterable, Mapping

from django.conf import settings
from django.core.checks import Error, Warning

from oidc.stepup import _as_level


def _auth_servers() -> Mapping:
    servers = getattr(settings, "OPENID_CONNECT_AUTH_SERVERS", None)
    return servers if isinstance(servers, Mapping) else {}


def _step_up_blocks() -> dict:
    """Each auth server's ``STEP_UP`` block, for the servers that set one."""
    return {
        name: server.get("STEP_UP")
        for name, server in _auth_servers().items()
        if isinstance(server, Mapping) and server.get("STEP_UP")
    }


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


def check_step_up_demands_fresh_authentication(app_configs=None, **kwargs):
    """A non-zero ``STEP_UP["MAX_AGE"]`` lets the provider skip the prompt.

    :mod:`oidc.stepup` explains why only ``max_age=0`` forces a fresh factor.
    ``redeem_step_up`` catches a replayed session only when the provider
    returns ``auth_time``.
    """
    offenders = sorted(
        name
        for name, block in _step_up_blocks().items()
        if isinstance(block, Mapping) and block.get("MAX_AGE", 0)
    )
    if not offenders:
        return []
    return [
        Warning(
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
    if not _step_up_blocks():
        return []
    caches = getattr(settings, "CACHES", {}) or {}
    backend = caches.get("default", {}).get("BACKEND", "")
    if "locmem" not in backend.lower():
        return []
    return [
        Warning(
            "Step-up is configured but CACHES['default'] is a local-memory "
            "backend, which is not shared across processes.",
            hint="Use a shared cache (Redis or Memcached) for CACHES['default'].",
            id="oidc.W002",
        )
    ]


def _is_positive_int(value) -> bool:
    if isinstance(value, bool):
        return False
    try:
        return int(value) > 0
    except (TypeError, ValueError, OverflowError):
        return False


def _satisfied_by_problem(value):
    if isinstance(value, str) or not isinstance(value, Iterable):
        return "STEP_UP['SATISFIED_BY'] must be a list"
    if not any(_as_level(item) is not None for item in value):
        return "STEP_UP['SATISFIED_BY'] must list at least one text or int level"
    return None


def _text_problem(block, key: str, optional: bool = False):
    value = block.get(key)
    if optional and value is None:
        return None
    if not value:
        return f"STEP_UP[{key!r}] is unset"
    if not isinstance(value, str):
        return f"STEP_UP[{key!r}] must be a string"
    return None


def _step_up_problems(block) -> list:
    if not isinstance(block, Mapping):
        return ["STEP_UP must be a dict"]
    max_age = block.get("MAX_AGE") or 0
    problems = [
        "STEP_UP['REDIRECT_URI'] is unset" if not block.get("REDIRECT_URI") else None,
        _text_problem(block, "CLAIM"),
        _text_problem(block, "SUBJECT_CLAIM", optional=True),
        _text_problem(block, "SUBJECT_FIELD", optional=True),
        _satisfied_by_problem(block.get("SATISFIED_BY")),
        (
            "STEP_UP['MAX_AUTH_AGE_SECONDS'] must be a positive int"
            if "MAX_AUTH_AGE_SECONDS" in block
            and not (
                isinstance(block["MAX_AUTH_AGE_SECONDS"], int)
                and _is_positive_int(block["MAX_AUTH_AGE_SECONDS"])
            )
            else None
        ),
        (
            "STEP_UP['MAX_AGE'] must be an int of 0 or more"
            if isinstance(max_age, bool) or not isinstance(max_age, int) or max_age < 0
            else None
        ),
    ]
    return [problem for problem in problems if problem]


def check_step_up_configuration(app_configs=None, **kwargs):
    """Settings that would otherwise fail only after the user has proved a
    factor at the provider."""
    problems = [
        f"{name}: {problem}"
        for name, block in sorted(_step_up_blocks().items())
        for problem in _step_up_problems(block)
    ]
    if hasattr(settings, "STEP_UP_GRANT_TTL") and not _is_positive_int(
        settings.STEP_UP_GRANT_TTL
    ):
        problems.append("STEP_UP_GRANT_TTL must be a positive int")
    return [
        Error(f"Step-up is misconfigured: {problem}.", id="oidc.E003")
        for problem in problems
    ]
