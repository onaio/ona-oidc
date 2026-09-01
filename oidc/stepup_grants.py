"""Single-use proof that someone showed a stronger factor a moment ago.

A step-up ends at a callback, but the action it authorises arrives on a later
request. Something has to carry "they proved it" across that gap, and the ways
of getting it wrong are quiet: a grant that is reusable, unscoped, or long
lived still looks like it works while defeating the gate it guards.

Kept generic on purpose. The subject is any stable key the application already
has for the caller -- this module does not know the user model -- and the
audience is the application's own vocabulary for what was proved.

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

    Scoped to both because an unscoped grant is spendable on any guarded
    action -- letting a proof collected to view recovery codes switch
    two-factor off instead -- and a grant not bound to whoever earned it is
    spendable by anyone who obtains the string.
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

    False when absent, expired, already spent, or minted for another subject
    or audience.

    The delete *is* the check. ``cache.delete`` reports whether it removed
    anything, so of two requests racing on one grant exactly one is told yes.
    Reading first and deleting after would leave a window between the two calls
    in which both see the grant present -- which is the whole property this
    single-use proof is relied on for.

    Expiry is therefore the cache backend's to enforce: this asks whether a key
    was removed, not whether it was still live. Redis reports an expired key as
    absent, so the TTL holds; Django's LocMemCache only checks expiry on read,
    and would report an expired grant as spent successfully.
    """
    if not grant:
        return False
    return bool(cache.delete(_grant_key(subject, audience, grant)))
