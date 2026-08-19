"""Deterministic finding identities for report comparison.

Fingerprints are stable identifiers only. They do not anonymize target data,
authenticate a report, or provide a digital signature.
"""

import hashlib
import json

from lotuswatch.models.finding import Finding
from lotuswatch.target import normalize_target

FINDING_FINGERPRINT_VERSION = 1
_FINGERPRINT_ALGORITHM = "sha256"


def finding_fingerprint(normalized_target: str, finding: Finding) -> str:
    """Return the versioned identity for a finding on a normalized target."""

    if not isinstance(normalized_target, str):
        raise TypeError("normalized_target must be a string.")

    if not isinstance(finding, Finding):
        raise TypeError("finding must be a Finding instance.")

    canonical_target = normalize_target(normalized_target).url
    validated_finding = Finding.model_validate(finding.model_dump(mode="python"))
    identity = {
        "finding_id": validated_finding.id,
        "normalized_target": canonical_target,
        "version": FINDING_FINGERPRINT_VERSION,
    }
    canonical_identity = json.dumps(
        identity,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    digest = hashlib.sha256(canonical_identity).hexdigest()

    return f"lwfp:v{FINDING_FINGERPRINT_VERSION}:{_FINGERPRINT_ALGORITHM}:{digest}"
