"""Tests for module oidc.stepup_grants"""

from unittest.mock import patch

from django.core.cache import cache
from django.test import TestCase
from django.test.utils import override_settings

from oidc.stepup_grants import grant_ttl, issue_grant, spend_grant


class TestGrants(TestCase):
    def setUp(self):
        cache.clear()

    def test_a_grant_lasts_the_configured_window(self):
        with patch("oidc.stepup_grants.cache.set") as cache_set:
            issue_grant(1, "reveal-key")

        self.assertEqual(cache_set.call_args.args[2], grant_ttl())

    def test_a_colon_cannot_move_the_subject_audience_boundary(self):
        """Unescaped, subject "1:x" with audience "y" and subject "1" with
        audience "x:y" build the same key."""
        grant = issue_grant("1:x", "y")

        self.assertFalse(spend_grant("1", "x:y", grant))
        self.assertTrue(spend_grant("1:x", "y", grant))

    def test_a_grant_spends_only_once(self):
        """The proof authorises one action. Reusable, it would let a single
        prompt stand in for every later one."""
        grant = issue_grant(1, "reveal-key")

        self.assertTrue(spend_grant(1, "reveal-key", grant))
        self.assertFalse(spend_grant(1, "reveal-key", grant))

    def test_two_racing_spenders_cannot_both_win(self):
        """Single-use has to hold under concurrency, not just in sequence.

        spend_grant makes cache.delete its check, so the race is between two
        deletes. The interleaving is forced rather than raced: the hook drops a
        competing spend in just before the first delete resolves. Only one of
        the two deletes can remove the key, so exactly one spend returns True.
        Ignoring the delete's result would let both read the grant as present
        and both win.
        """
        grant = issue_grant(1, "reveal-key")
        competitor = []
        entered = []
        real_delete = cache.delete

        def let_a_competitor_in(key, *args, **kwargs):
            if not entered:
                # Flag first: the competing spend goes through this same hook.
                entered.append(True)
                competitor.append(spend_grant(1, "reveal-key", grant))
            return real_delete(key, *args, **kwargs)

        with patch.object(cache, "delete", side_effect=let_a_competitor_in):
            first = spend_grant(1, "reveal-key", grant)

        self.assertTrue(entered, "delete hook never fired; the race was not exercised")
        self.assertEqual(sum([first, *competitor]), 1)

    def test_a_grant_is_scoped_to_its_audience(self):
        """Unscoped, a proof collected to view recovery codes would switch
        two-factor off instead."""
        grant = issue_grant(1, "reveal-key")

        self.assertFalse(spend_grant(1, "disable-2fa", grant))

    def test_a_grant_is_scoped_to_its_subject(self):
        """Otherwise anyone who obtains the string can spend it."""
        grant = issue_grant(1, "reveal-key")

        self.assertFalse(spend_grant(2, "reveal-key", grant))

    def test_an_expired_grant_never_spends(self):
        """Database, file and local-memory caches delete an expired key and
        report success, so the delete alone would spend it."""
        with (
            patch("oidc.stepup_grants.cache.get", return_value=None),
            patch("oidc.stepup_grants.cache.delete", return_value=True),
        ):
            self.assertFalse(spend_grant(1, "reveal-key", "expired"))

    def test_an_empty_grant_never_spends(self):
        self.assertFalse(spend_grant(1, "reveal-key", ""))
        self.assertFalse(spend_grant(1, "reveal-key", None))

    def test_grants_are_not_guessable(self):
        """Short grants would be brute-forceable within the TTL."""
        self.assertGreaterEqual(len(issue_grant(1, "reveal-key")), 32)

    @override_settings(STEP_UP_GRANT_TTL=90)
    def test_a_deployment_can_choose_its_own_window(self):
        self.assertEqual(grant_ttl(), 90)
