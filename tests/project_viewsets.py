"""
Stand-in for a project-owned viewset subclass.

Mirrors how a consumer actually does this — onadata's
``OnaOpenIDConnectViewset`` subclasses the concrete viewset to refuse SSO
login for organization accounts. Kept in its own module, importing only
``oidc.viewsets``: ``oidc.urls`` resolves ``VIEWSET_CLASS`` at import time, so
a subclass module that reached back into ``oidc.urls`` would deadlock on a
circular import.
"""

from oidc.viewsets import UserModelOpenIDConnectViewset


class InjectedViewset(UserModelOpenIDConnectViewset):
    """Subclass used to prove routing goes to the configured class."""
