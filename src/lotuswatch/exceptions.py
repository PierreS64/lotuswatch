class LotusWatchError(Exception):
    """Base exception for LotusWatch."""


class TargetValidationError(LotusWatchError):
    """Raised when a scan target is invalid or unsupported."""


class ReportError(LotusWatchError):
    """Base exception for report reading and generation errors."""


class ReportReadError(ReportError):
    """Raised when a report file cannot be read."""


class ReportTooLargeError(ReportReadError):
    """Raised when a report exceeds the supported input size."""


class ReportFormatError(ReportReadError):
    """Raised when a report is not valid UTF-8 JSON."""


class ReportCompatibilityError(ReportReadError):
    """Raised when a report uses an unsupported or missing schema version."""


class ReportValidationError(ReportReadError):
    """Raised when report data does not satisfy the scan report model."""


class ReportAlreadyExistsError(ReportError):
    """Raised when a report would overwrite an existing file."""


class ReportWriteError(ReportError):
    """Raised when a report cannot be written."""
