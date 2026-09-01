"""Where an identity provider returns after a step-up.

Separate from the login callback on purpose: that one establishes identity and
cycles the session key. A step-up is performed by someone already signed in,
so reusing it would disturb a live session as a side effect of proving a
factor.

A mixin rather than a ready-made viewset, because the protocol is shared but
the outcome is not: one application mints a scoped grant, another sets a flag
or writes an audit record. The library takes the flow as far as "this token
is fresh, strong enough, and describes this user" and hands over there.
"""

import logging
from typing import Any, Optional, Tuple

from django.conf import settings
from django.http import HttpResponse

from oidc.stepup import (
    find_step_up_auth_server,
    redeem_step_up,
    render_step_up_popup,
    step_up_config,
    subject_binding,
    verify_assurance,
    verify_subject,
)

logger = logging.getLogger(__name__)


class StepUpCallbackMixin:
    """Redeem, verify, and hand the verified claims to the application.

    Implement :meth:`on_step_up_verified`; optionally override
    :meth:`expected_subject` when the value identifying the caller is not read
    straight off ``request.user``.
    """

    #: Origin the popup posts its result to. Read from settings so a
    #: deployment cannot accidentally leave it open; never defaults to "*".
    step_up_popup_origin_setting = "STEP_UP_POPUP_ORIGIN"

    def verify_step_up_context(self, request, context: dict) -> Optional[str]:
        """Check whatever the application put in the state. Reason, or None.

        Runs before the token is examined, so a state belonging to someone
        else is reported as such rather than surfacing as a subject mismatch,
        and so the cheap check happens first.
        """
        return None

    def on_step_up_verified(self, request, claims: dict, context: dict) -> Any:
        """What a proven factor entitles the caller to. Application-defined."""
        raise NotImplementedError

    def expected_subject(self, request, claims: dict) -> Any:
        """The value the token's subject claim must match.

        Defaults to the attribute login identifies people by, so step-up and
        login cannot disagree about who a token describes.
        """
        _claim, field = subject_binding(step_up_config(self.step_up_auth_server()))
        return getattr(request.user, field, None)

    def step_up_auth_server(self) -> str:
        return find_step_up_auth_server() or ""

    def complete_step_up(
        self, request, code: str, state: str, auth_server: Optional[str] = None
    ) -> Tuple[Any, Optional[str]]:
        """``(result, reason)`` -- result is whatever the application returns."""
        auth_server = auth_server or self.step_up_auth_server()
        if not auth_server:
            logger.warning("step-up: no auth server carries a STEP_UP block")
            return None, "step_up_unavailable"

        claims, context, reason = redeem_step_up(auth_server, code, state)
        if claims is None:
            return None, reason

        reason = self.verify_step_up_context(request, context)
        if reason:
            return None, reason

        config = step_up_config(auth_server)

        # Who, before how strongly. The state proves the flow was started by
        # this caller; only the token says who finished it, and signing in as
        # somebody else would otherwise be credited to the starter.
        satisfied, reason = verify_subject(
            claims, self.expected_subject(request, claims), config
        )
        if not satisfied:
            return None, reason

        satisfied, reason = verify_assurance(claims, config)
        if not satisfied:
            return None, reason

        return self.on_step_up_verified(request, claims, context), None

    def step_up_popup_response(self, result, reason: Optional[str] = None):
        """A page handing the result back to the window that opened it."""
        origin = getattr(self, "step_up_popup_origin", None) or getattr(
            settings, self.step_up_popup_origin_setting, ""
        )
        html = render_step_up_popup(origin, grant=result, reason=reason)
        if not html:
            logger.error(
                "step-up: %s is unset; cannot return the result to the opener",
                self.step_up_popup_origin_setting,
            )
            return HttpResponse(
                "<!doctype html><title>Verification</title>"
                "<p>This server is not configured to complete verification.</p>",
                content_type="text/html",
                status=500,
            )
        return HttpResponse(html, content_type="text/html")
