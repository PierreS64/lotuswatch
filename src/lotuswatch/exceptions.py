class LotusWatchError(Exception):
    """Base exception for LotusWatch."""


class TargetValidationError(LotusWatchError):
    """Raised when a scan target is invalid or unsupported."""


class ReportError(LotusWatchError):
    """Base exception for report generation errors."""


class ReportAlreadyExistsError(ReportError):
    """Raised when a report would overwrite an existing file."""


class ReportWriteError(ReportError):
    """Raised when a report cannot be written."""
