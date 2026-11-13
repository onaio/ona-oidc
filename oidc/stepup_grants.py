"""Single-use proof that someone showed a stronger factor a moment ago.

A step-up ends at a callback, but the action it authorises arrives on a later
request. Something has to carry "they proved it" across that gap, and the ways
of getting it wrong are quiet: a grant that is reusable, unscoped, or long
lived still looks like it works while defeating the gate it guards.

Kept generic on purpose. The subject is any stable key the application already
has for the caller, since this module does not know the user model. The
audience is the application's own name for what was proved.

Applications that do not want grants need not use this: the callback mixin
hands over the verified claims and an application is free to set a session
flag, write an audit record, or complete the action inline instead.
"""

import secrets
from typing import Any, Optional
from urllib.parse import quote

from django.conf import settings
from django.core.cache import cache

#: Long enough to fill in the next form, short enough that a grant left behind
#: on a shared machine is worthless. Overridable per deployment, because the
#: right window depends on what the gated action is.
DEFAULT_GRANT_TTL = 5 * 60

_GRANT_PREFIX = "oidc:step-up-grant:"


def grant_ttl() -> int:
    return int(getattr(settings, "STEP_UP_GRANT_TTL", DEFAULT_GRANT_TTL))


def _grant_key(subject: Any, audience: str, grant: str) -> str:
    # Escape the delimited parts: a ':' in a subject would otherwise shift the
    # audience boundary and let a grant resolve under a scope it was not minted
    # for.
    return (
        f"{_GRANT_PREFIX}{quote(str(subject), safe='')}:"
        f"{quote(audience, safe='')}:{grant}"
    )


def issue_grant(subject: Any, audience: str, ttl: Optional[int] = None) -> str:
    """Mint a grant valid only for ``audience``, and only for ``subject``.

    An unscoped grant is spendable on any guarded action, so a proof collected
    to view recovery codes could switch two-factor off instead. A grant not
    bound to whoever earned it is spendable by anyone who obtains the string.
    """
    grant = secrets.token_urlsafe(32)
    # `is None`, not `or`: ttl=0 asks for a grant that outlives nothing, and
    # an `or` fallback would hand back the default window instead.
    cache.set(
        _grant_key(subject, audience, grant),
        True,
        grant_ttl() if ttl is None else ttl,
    )
    return grant


def spend_grant(subject: Any, audience: str, grant: str) -> bool:
    """Redeem a grant, once.

    False when the grant is absent, expired, already spent, or minted for
    another subject or audience.

    The read enforces expiry: Django's database, file and local-memory caches
    all delete an expired key and report success. The delete is what makes
    the grant single-use. ``cache.delete`` reports whether it removed
    anything, so of two requests racing on one grant exactly one gets True.
    """
    if not grant:
        return False
    key = _grant_key(subject, audience, grant)
    if cache.get(key) is None:
        return False
    return bool(cache.delete(key))
