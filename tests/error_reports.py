"""Helpers for checking what Django error reports show"""

import traceback
from collections.abc import Callable
from types import FrameType

from django.views.debug import SafeExceptionReporterFilter


def escaped_frames(
    call: Callable[[], object], exc_type: type[BaseException], from_function: str
) -> list[FrameType]:
    """
    Run `call`, expecting `exc_type` to escape it, and return the traceback's
    frames from the one running `from_function` down to where it was raised.

    Catches the exception itself because unittest's assertRaises clears the
    frames' locals, which are what an error report shows.
    """
    try:
        call()
    except exc_type as exc:
        frames = [frame for frame, _ in traceback.walk_tb(exc.__traceback__)]
    else:
        raise AssertionError(f"{exc_type.__name__} should escape {from_function}")
    names = [frame.f_code.co_name for frame in frames]
    if from_function not in names:
        raise AssertionError(f"{from_function} is not in the traceback: {names}")
    return frames[names.index(from_function) :]


def reported_locals(frame: FrameType) -> dict:
    """A frame's locals as a Django error report shows them"""
    return dict(
        SafeExceptionReporterFilter().get_traceback_frame_variables(None, frame)
    )
