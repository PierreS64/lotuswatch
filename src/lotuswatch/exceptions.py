class LotusWatchError(Exception):
    """Base exception for LotusWatch."""


class TargetValidationError(LotusWatchError):
    """Raised when a scan target is invalid or unsupported."""
