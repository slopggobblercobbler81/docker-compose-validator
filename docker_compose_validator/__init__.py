"""Docker Compose Validator.

Production-grade Docker Compose linter, security auditor, and best-practices analyzer.
"""

from docker_compose_validator.__version__ import __version__, __author__, __license__
from docker_compose_validator.models import (
    Category,
    Finding,
    Severity,
    ValidationReport,
    ValidationResult,
)
from docker_compose_validator.parser import ComposeParser, ParsedComposeFile
from docker_compose_validator.rules.base import BaseRule, RuleRegistry
from docker_compose_validator.runner import ValidationRunner, find_compose_files

__all__ = [
    "__version__",
    "__author__",
    "__license__",
    "Category",
    "Finding",
    "Severity",
    "ValidationReport",
    "ValidationResult",
    "ComposeParser",
    "ParsedComposeFile",
    "BaseRule",
    "RuleRegistry",
    "ValidationRunner",
    "find_compose_files",
]
