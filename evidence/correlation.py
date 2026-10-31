"""Deterministic cross-evidence forensic correlation utilities."""

from __future__ import annotations

import hashlib
import mimetypes
import os
import re
from dataclasses import dataclass
from datetime import datetime
from itertools import combinations
from typing import Any, Iterable, Mapping


MAX_TEXT_FILE_SIZE = 10 * 1024 * 1024
MAX_EXTRACTED_INDICATORS_PER_FILE = 500
TEMPORAL_PROXIMITY_SECONDS = 5 * 60
TEXT_CHUNK_SIZE = 64 * 1024

SUPPORTED_TEXT_EXTENSIONS = {
    ".txt",
    ".log",
    ".csv",
    ".json",
    ".xml",
    ".html",
    ".md",
}

COMMON_FILENAMES = {
    "document.txt",
    "file.txt",
    "image.jpg",
    "log.txt",
    "notes.txt",
    "readme.txt",
}

COMMON_INFRASTRUCTURE_INDICATORS = {
    "0.0.0.0",
    "127.0.0.1",
    "localhost",
    "::1",
}

IP_PATTERN = re.compile(r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w.])")
EMAIL_PATTERN = re.compile(r"(?<![\w.+-])([\w.+-]+@[\w-]+(?:\.[\w-]+)+)(?![\w.-])", re.IGNORECASE)
URL_PATTERN = re.compile(r"https?://[^\s<>\"']+", re.IGNORECASE)
DOMAIN_PATTERN = re.compile(r"(?<![@\w.-])(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}(?![\w.-])", re.IGNORECASE)
WINDOWS_PATH_PATTERN = re.compile(r"(?<![\w])(?:[a-zA-Z]:\\|\\\\)[^\r\n<>\"']+", re.IGNORECASE)


@dataclass(frozen=True)
class CorrelationConfig:
    """Limits and display policy for one deterministic correlation run."""

    max_text_file_size: int = MAX_TEXT_FILE_SIZE
    max_indicators_per_file: int = MAX_EXTRACTED_INDICATORS_PER_FILE
    temporal_window_seconds: int = TEMPORAL_PROXIMITY_SECONDS
    include_contextual: bool = False


def _value(record: Mapping[str, Any], key: str, default: Any = None) -> Any:
    try:
        return record[key]
    except (KeyError, TypeError):
        return default


def _normalize_hash(value: Any) -> str:
    return str(value or "").strip().lower()


def _hash_file(path: str) -> str | None:
    digest = hashlib.sha256()
    try:
        with open(path, "rb") as evidence_file:
            for chunk in iter(lambda: evidence_file.read(1024 * 1024), b""):
                digest.update(chunk)
    except (OSError, PermissionError):
        return None
    return digest.hexdigest()


def current_copy_status(evidence: Mapping[str, Any]) -> str:
    """Return the current status of an evidence preserved copy."""

    path = _value(evidence, "preserved_path")
    stored_hash = _normalize_hash(_value(evidence, "sha256"))
    if not path or not os.path.isfile(path):
        return "MISSING"
    if not stored_hash:
        return "UNVERIFIED"

    current_hash = _hash_file(path)
    if not current_hash:
        return "UNVERIFIED"
    return "VERIFIED" if current_hash == stored_hash else "MISMATCH"


def _parse_acquisition_time(value: Any) -> datetime | None:
    if not value:
        return None
    text = str(value).strip()
    for format_string in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S"):
        try:
            return datetime.strptime(text, format_string)
        except ValueError:
            continue
    return None


def _is_valid_ipv4(value: str) -> bool:
    parts = value.split(".")
    return len(parts) == 4 and all(part.isdigit() and 0 <= int(part) <= 255 for part in parts)


def _redact_indicator(indicator_type: str, value: str) -> str:
    if indicator_type == "email":
        local, _, domain = value.partition("@")
        return f"{local[:1]}***@{domain}"
    if indicator_type in {"url", "domain"}:
        return value[:48] + ("..." if len(value) > 48 else "")
    if indicator_type == "path":
        return value[:64] + ("..." if len(value) > 64 else "")
    return value


def _normalise_indicator(indicator_type: str, value: str) -> str | None:
    cleaned = value.strip().strip(".,;:!?()[]{}<>").lower()
    if indicator_type == "ip":
        return cleaned if _is_valid_ipv4(cleaned) else None
    if indicator_type == "email":
        return cleaned
    if indicator_type == "url":
        return cleaned.rstrip("/")
    if indicator_type == "domain":
        return cleaned.rstrip(".")
    if indicator_type == "path":
        return re.sub(r"/+", r"\\", cleaned).rstrip("\\")
    return None


def _indicator_is_suppressed(indicator_type: str, value: str) -> bool:
    if value in COMMON_INFRASTRUCTURE_INDICATORS:
        return True
    if indicator_type == "ip":
        first_octets = value.split(".")[:2]
        if first_octets == ["192", "168"] or value.startswith("10.") or value.startswith("172."):
            return True
    if indicator_type in {"domain", "url"} and value in {"localhost", "http://localhost", "https://localhost"}:
        return True
    return False


def _extract_indicators(text: str, maximum: int) -> dict[str, set[str]]:
    extracted: dict[str, set[str]] = {"ip": set(), "email": set(), "url": set(), "domain": set(), "path": set()}
    for indicator_type, pattern in (
        ("url", URL_PATTERN),
        ("email", EMAIL_PATTERN),
        ("ip", IP_PATTERN),
        ("path", WINDOWS_PATH_PATTERN),
        ("domain", DOMAIN_PATTERN),
    ):
        for match in pattern.findall(text):
            raw_value = match if isinstance(match, str) else match[0]
            normalized = _normalise_indicator(indicator_type, raw_value)
            if normalized and not _indicator_is_suppressed(indicator_type, normalized):
                extracted[indicator_type].add(normalized)
                if sum(len(values) for values in extracted.values()) >= maximum:
                    return extracted
    return extracted


def extract_text_indicators(evidence: Mapping[str, Any], config: CorrelationConfig) -> tuple[dict[str, set[str]], str | None]:
    """Read supported preserved text evidence in bounded chunks."""

    path = _value(evidence, "preserved_path")
    name = str(_value(evidence, "evidence_name", ""))
    extension = os.path.splitext(name)[1].lower()
    mime_type, _ = mimetypes.guess_type(name)
    is_supported = extension in SUPPORTED_TEXT_EXTENSIONS or bool(mime_type and mime_type.startswith("text/"))
    if not is_supported:
        return {}, "unsupported text format"
    if not path or not os.path.isfile(path):
        return {}, "preserved copy unavailable"

    try:
        size = os.path.getsize(path)
    except OSError:
        return {}, "preserved copy metadata unavailable"
    if size > config.max_text_file_size:
        return {}, "text file exceeds configured size limit"

    parts: list[str] = []
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as evidence_file:
            while True:
                chunk = evidence_file.read(TEXT_CHUNK_SIZE)
                if not chunk:
                    break
                parts.append(chunk)
    except (OSError, UnicodeError):
        return {}, "text file could not be read"
    return _extract_indicators("".join(parts), config.max_indicators_per_file), None


def _filename(evidence: Mapping[str, Any]) -> str:
    return os.path.basename(str(_value(evidence, "evidence_name", "")).strip()).lower()


def _extension(evidence: Mapping[str, Any]) -> str:
    return os.path.splitext(_filename(evidence))[1].lower()


def _make_finding(
    evidence_a: Mapping[str, Any],
    evidence_b: Mapping[str, Any],
    relationship_type: str,
    indicator_type: str | None,
    indicator_value: str,
    score: int,
    strength: str,
    explanation: str,
    detected_at: str,
) -> dict[str, Any]:
    id_a = int(_value(evidence_a, "id"))
    id_b = int(_value(evidence_b, "id"))
    if id_a > id_b:
        evidence_a, evidence_b = evidence_b, evidence_a
        id_a, id_b = id_b, id_a
    fingerprint_source = f"{relationship_type}|{indicator_type or ''}|{indicator_value}"
    return {
        "evidence_a_id": id_a,
        "evidence_b_id": id_b,
        "evidence_a_name": _value(evidence_a, "evidence_name", ""),
        "evidence_b_name": _value(evidence_b, "evidence_name", ""),
        "relationship_type": relationship_type,
        "indicator_type": indicator_type,
        "indicator_value": _redact_indicator(indicator_type or "", indicator_value),
        "indicator_fingerprint": hashlib.sha256(fingerprint_source.encode("utf-8")).hexdigest(),
        "strength_score": score,
        "strength_label": strength,
        "explanation": explanation,
        "detected_at": detected_at,
    }


def _shared_indicator_strength(indicator_type: str) -> tuple[int, str]:
    if indicator_type == "url":
        return 70, "Moderate"
    if indicator_type == "email":
        return 65, "Moderate"
    if indicator_type == "domain":
        return 55, "Moderate"
    if indicator_type == "path":
        return 50, "Moderate"
    return 45, "Contextual"


def analyze_evidence(evidence_items: Iterable[Mapping[str, Any]], config: CorrelationConfig | None = None) -> dict[str, Any]:
    """Analyze one case's evidence records without changing any evidence file."""

    config = config or CorrelationConfig()
    evidence = sorted(list(evidence_items), key=lambda item: int(_value(item, "id")))
    detected_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    statuses = {int(_value(item, "id")): current_copy_status(item) for item in evidence}
    warnings: list[str] = []
    indicator_map: dict[int, dict[str, set[str]]] = {}
    skipped_count = 0

    for item in evidence:
        item_id = int(_value(item, "id"))
        status = statuses[item_id]
        if status != "VERIFIED":
            skipped_count += 1
            warnings.append(
                f"Evidence EV-{item_id:04d} is {status}; correlation involving its preserved copy may be incomplete."
            )
            continue
        indicators, warning = extract_text_indicators(item, config)
        indicator_map[item_id] = indicators
        if warning and warning != "unsupported text format":
            warnings.append(f"Evidence EV-{item_id:04d}: {warning}.")

    findings: list[dict[str, Any]] = []
    for first, second in combinations(evidence, 2):
        first_id = int(_value(first, "id"))
        second_id = int(_value(second, "id"))
        first_status = statuses[first_id]
        second_status = statuses[second_id]
        pair_is_verified = first_status == "VERIFIED" and second_status == "VERIFIED"

        if not pair_is_verified:
            continue

        if pair_is_verified and _normalize_hash(_value(first, "sha256")) == _normalize_hash(_value(second, "sha256")):
            if _normalize_hash(_value(first, "sha256")):
                findings.append(_make_finding(
                    first,
                    second,
                    "Identical SHA-256",
                    "sha256",
                    _normalize_hash(_value(first, "sha256")),
                    100,
                    "Strongest Deterministic",
                    "Both preserved evidence copies currently produce the same verified SHA-256 value.",
                    detected_at,
                ))

        filename = _filename(first)
        if filename and filename == _filename(second) and filename not in COMMON_FILENAMES and pair_is_verified:
            findings.append(_make_finding(
                first,
                second,
                "Same Distinctive Filename",
                "filename",
                filename,
                45,
                "Moderate",
                "Both verified evidence items use the same distinctive filename; this is a potential naming relationship only.",
                detected_at,
            ))

        if config.include_contextual and _extension(first) and _extension(first) == _extension(second):
            findings.append(_make_finding(
                first,
                second,
                "Same File Extension",
                "extension",
                _extension(first),
                5,
                "Weak",
                "Both evidence items have the same file extension; this is common contextual metadata and requires investigator review.",
                detected_at,
            ))

        first_time = _parse_acquisition_time(_value(first, "acquired_at"))
        second_time = _parse_acquisition_time(_value(second, "acquired_at"))
        if first_time and second_time and abs((first_time - second_time).total_seconds()) <= config.temporal_window_seconds:
            findings.append(_make_finding(
                first,
                second,
                "Temporal Proximity",
                "acquisition_timestamp",
                f"{_value(first, 'acquired_at')} / {_value(second, 'acquired_at')}",
                20,
                "Contextual",
                f"The evidence acquisition timestamps are within {config.temporal_window_seconds} seconds; this does not represent underlying evidence activity.",
                detected_at,
            ))

        first_indicators = indicator_map.get(first_id, {})
        second_indicators = indicator_map.get(second_id, {})
        for indicator_type in ("url", "email", "domain", "path", "ip"):
            for shared in sorted(first_indicators.get(indicator_type, set()) & second_indicators.get(indicator_type, set())):
                score, strength = _shared_indicator_strength(indicator_type)
                findings.append(_make_finding(
                    first,
                    second,
                    f"Shared {indicator_type.upper()} Indicator",
                    indicator_type,
                    shared,
                    score,
                    strength,
                    f"The same deterministic {indicator_type} indicator was extracted from both verified preserved evidence copies; it is a potential relationship requiring investigator review.",
                    detected_at,
                ))

    unique_findings: dict[tuple[int, int, str, str], dict[str, Any]] = {}
    for finding in findings:
        key = (
            finding["evidence_a_id"],
            finding["evidence_b_id"],
            finding["relationship_type"],
            finding["indicator_fingerprint"],
        )
        unique_findings[key] = finding

    return {
        "findings": sorted(
            unique_findings.values(),
            key=lambda finding: (finding["evidence_a_id"], finding["evidence_b_id"], finding["relationship_type"], finding["indicator_fingerprint"]),
        ),
        "evidence_count": len(evidence),
        "analyzed_count": len(evidence) - skipped_count,
        "skipped_count": skipped_count,
        "incomplete": bool(warnings),
        "warnings": sorted(set(warnings)),
        "detected_at": detected_at,
    }
