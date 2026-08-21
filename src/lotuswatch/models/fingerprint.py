"""Deterministic finding identities for report comparison.

Fingerprints are stable identifiers only. They do not anonymize target data,
authenticate a report, or provide a digital signature.
"""

import hashlib
import json
import re

from lotuswatch.models.finding import FINDING_ID_PATTERN, Finding
from lotuswatch.target import normalize_target

FINDING_FINGERPRINT_VERSION = 1
_FINGERPRINT_ALGORITHM = "sha256"


def finding_id_fingerprint(normalized_target: str, finding_id: str) -> str:
    """Return the versioned identity for a validated finding identifier."""

    if not isinstance(normalized_target, str):
        raise TypeError("normalized_target must be a string.")
    if not isinstance(finding_id, str):
        raise TypeError("finding_id must be a string.")

    finding_id = finding_id.strip()
    if re.fullmatch(FINDING_ID_PATTERN, finding_id) is None:
        raise ValueError("finding_id is invalid.")

    canonical_target = normalize_target(normalized_target).url
    identity = {
        "finding_id": finding_id,
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


def finding_fingerprint(normalized_target: str, finding: Finding) -> str:
    """Return the versioned identity for a finding on a normalized target."""

    if not isinstance(finding, Finding):
        raise TypeError("finding must be a Finding instance.")

    validated_finding = Finding.model_validate(finding.model_dump(mode="python"))
    return finding_id_fingerprint(normalized_target, validated_finding.id)
