"""Data models for docker-compose-validator."""

from __future__ import annotations

import enum
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


class Severity(enum.Enum):
    """Severity levels for findings."""
    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

    @property
    def level(self) -> int:
        levels = {
            Severity.INFO: 1,
            Severity.LOW: 2,
            Severity.MEDIUM: 3,
            Severity.HIGH: 4,
            Severity.CRITICAL: 5,
        }
        return levels[self]

    def __ge__(self, other: Severity) -> bool:
        if self.__class__ is other.__class__:
            return self.level >= other.level
        return NotImplemented

    def __gt__(self, other: Severity) -> bool:
        if self.__class__ is other.__class__:
            return self.level > other.level
        return NotImplemented

    def __le__(self, other: Severity) -> bool:
        if self.__class__ is other.__class__:
            return self.level <= other.level
        return NotImplemented

    def __lt__(self, other: Severity) -> bool:
        if self.__class__ is other.__class__:
            return self.level < other.level
        return NotImplemented

    @classmethod
    def from_str(cls, value: str) -> Severity:
        normalized = value.strip().upper()
        for member in cls:
            if member.value == normalized:
                return member
        raise ValueError(f"Unknown severity level: {value}. Valid levels: {[m.value for m in cls]}")


class Category(enum.Enum):
    """Categories for validation rules."""
    SYNTAX = "Syntax"
    SECURITY = "Security"
    RELIABILITY = "Reliability"
    BEST_PRACTICE = "Best Practice"

    @classmethod
    def from_str(cls, value: str) -> Category:
        normalized = value.strip().lower().replace("_", " ")
        for member in cls:
            if member.value.lower() == normalized:
                return member
        raise ValueError(f"Unknown category: {value}")


@dataclass
class Finding:
    """Represents a single rule violation or notice."""
    rule_id: str
    rule_name: str
    severity: Severity
    category: Category
    message: str
    file_path: str
    line_number: Optional[int] = None
    service_name: Optional[str] = None
    recommendation: str = ""
    details: Optional[Dict[str, Any]] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "rule_name": self.rule_name,
            "severity": self.severity.value,
            "category": self.category.value,
            "message": self.message,
            "file_path": self.file_path,
            "line_number": self.line_number,
            "service_name": self.service_name,
            "recommendation": self.recommendation,
            "details": self.details or {},
        }


@dataclass
class ValidationResult:
    """Validation result for a single compose file."""
    file_path: str
    findings: List[Finding] = field(default_factory=list)
    is_valid_syntax: bool = True
    error_message: Optional[str] = None
    service_count: int = 0
    scanned_rules_count: int = 0

    @property
    def has_findings(self) -> bool:
        return len(self.findings) > 0

    def count_by_severity(self, severity: Severity) -> int:
        return sum(1 for f in self.findings if f.severity == severity)


@dataclass
class ValidationReport:
    """Overall validation report across all processed files."""
    results: List[ValidationResult] = field(default_factory=list)
    total_files: int = 0
    total_services: int = 0

    @property
    def all_findings(self) -> List[Finding]:
        findings: List[Finding] = []
        for res in self.results:
            findings.extend(res.findings)
        return findings

    @property
    def total_findings(self) -> int:
        return len(self.all_findings)

    @property
    def critical_count(self) -> int:
        return sum(1 for f in self.all_findings if f.severity == Severity.CRITICAL)

    @property
    def high_count(self) -> int:
        return sum(1 for f in self.all_findings if f.severity == Severity.HIGH)

    @property
    def medium_count(self) -> int:
        return sum(1 for f in self.all_findings if f.severity == Severity.MEDIUM)

    @property
    def low_count(self) -> int:
        return sum(1 for f in self.all_findings if f.severity == Severity.LOW)

    @property
    def info_count(self) -> int:
        return sum(1 for f in self.all_findings if f.severity == Severity.INFO)

    def has_failures(self, fail_on_severity: Optional[Severity] = None) -> bool:
        """Returns True if any finding meets or exceeds the fail_on_severity."""
        if fail_on_severity is None:
            return False
        # Also fail if any file had a syntax/fatal parse error
        if any(not res.is_valid_syntax for res in self.results):
            return True
        return any(f.severity >= fail_on_severity for f in self.all_findings)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "summary": {
                "total_files": self.total_files,
                "total_services": self.total_services,
                "total_findings": self.total_findings,
                "critical": self.critical_count,
                "high": self.high_count,
                "medium": self.medium_count,
                "low": self.low_count,
                "info": self.info_count,
            },
            "files": [
                {
                    "file_path": r.file_path,
                    "is_valid_syntax": r.is_valid_syntax,
                    "error_message": r.error_message,
                    "service_count": r.service_count,
                    "findings_count": len(r.findings),
                    "findings": [f.to_dict() for f in r.findings],
                }
                for r in self.results
            ],
        }
