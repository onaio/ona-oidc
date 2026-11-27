"""Cache backends that reproduce real backends' failure modes in tests."""

from django.core.cache.backends.locmem import LocMemCache


class SilentSetFailureCache(LocMemCache):
    """
    Drops every ``set`` without an error, as Django's database cache
    backend does when the write raises a database error.
    """

    def set(self, *args, **kwargs):
        return None
