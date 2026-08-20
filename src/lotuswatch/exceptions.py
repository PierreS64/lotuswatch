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


class ComparisonError(LotusWatchError):
    """Base exception for scan report comparison errors."""


class ComparisonInputError(ComparisonError):
    """Raised when a comparison input is invalid."""


class ComparisonTargetMismatchError(ComparisonInputError):
    """Raised when reports represent different normalized targets."""


class DuplicateFindingFingerprintError(ComparisonInputError):
    """Raised when one report contains a duplicate finding identity."""


class MonitoringStoreError(LotusWatchError):
    """Base exception for local monitoring storage errors."""


class StoreInitializationError(MonitoringStoreError):
    """Raised when a monitoring store cannot be initialized safely."""


class StoreCompatibilityError(StoreInitializationError):
    """Raised when a monitoring store uses an unsupported schema."""


class StoreValidationError(MonitoringStoreError):
    """Raised when data does not satisfy the monitoring storage contract."""


class StoreConflictError(MonitoringStoreError):
    """Raised when stored identifiers or unique values conflict."""


class StoreReadError(MonitoringStoreError):
    """Raised when monitoring data cannot be read safely."""


class StoreWriteError(MonitoringStoreError):
    """Raised when monitoring data cannot be persisted atomically."""


class StoredReportTooLargeError(StoreValidationError):
    """Raised when a scan report exceeds the storage size limit."""
