"""Base rule definition and rule registry."""

from __future__ import annotations

import abc
from typing import Any, Dict, List, Optional, Type
from docker_compose_validator.models import Category, Finding, Severity
from docker_compose_validator.parser import ParsedComposeFile


class BaseRule(abc.ABC):
    """Abstract base class for all docker-compose validation rules."""

    rule_id: str
    name: str
    description: str
    severity: Severity
    category: Category
    recommendation: str

    def create_finding(
        self,
        parsed: ParsedComposeFile,
        message: str,
        line_number: Optional[int] = None,
        service_name: Optional[str] = None,
        recommendation: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None,
    ) -> Finding:
        """Helper to create a finding with rule defaults."""
        return Finding(
            rule_id=self.rule_id,
            rule_name=self.name,
            severity=self.severity,
            category=self.category,
            message=message,
            file_path=parsed.file_path,
            line_number=line_number,
            service_name=service_name,
            recommendation=recommendation or self.recommendation,
            details=details or {},
        )

    @abc.abstractmethod
    def check(self, parsed: ParsedComposeFile) -> List[Finding]:
        """Runs validation rule against the parsed compose file and returns findings."""
        pass


class RuleRegistry:
    """Registry holding all registered validation rules."""

    _rules: Dict[str, BaseRule] = {}

    @classmethod
    def register(cls, rule_cls: Type[BaseRule]) -> Type[BaseRule]:
        """Decorator or method to register a rule class."""
        rule_instance = rule_cls()
        cls._rules[rule_instance.rule_id.upper()] = rule_instance
        return rule_cls

    @classmethod
    def get_rule(cls, rule_id: str) -> Optional[BaseRule]:
        return cls._rules.get(rule_id.upper())

    @classmethod
    def all_rules(cls) -> List[BaseRule]:
        return list(cls._rules.values())

    @classmethod
    def filter_rules(
        cls,
        ignore_rules: Optional[List[str]] = None,
        select_rules: Optional[List[str]] = None,
        min_severity: Optional[Severity] = None,
    ) -> List[BaseRule]:
        """Filters rules by selection, exclusion, and minimum severity."""
        ignored = {r.strip().upper() for r in (ignore_rules or []) if r.strip()}
        selected = {r.strip().upper() for r in (select_rules or []) if r.strip()}

        active: List[BaseRule] = []
        for r in cls._rules.values():
            r_id = r.rule_id.upper()
            if selected and r_id not in selected:
                continue
            if r_id in ignored:
                continue
            if min_severity and r.severity < min_severity:
                continue
            active.append(r)
        return active
