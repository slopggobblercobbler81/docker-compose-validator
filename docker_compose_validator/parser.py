"""YAML and Compose file parser with line-number tracking and directive parsing."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple, Union
import yaml


class LineDict(dict):
    """Dictionary subclass storing 1-based line numbers for keys and the mapping itself."""

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self._lines: Dict[str, int] = {}

    def get_line(self, key: Optional[str] = None, default: Optional[int] = None) -> Optional[int]:
        if key is not None:
            if key in self._lines:
                return self._lines[key]
        return self._lines.get("__self__", default)


class LineList(list):
    """List subclass storing 1-based line numbers for items and the sequence itself."""

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self._item_lines: List[int] = []
        self._self_line: Optional[int] = None

    def get_line(self, index: Optional[int] = None, default: Optional[int] = None) -> Optional[int]:
        if index is not None and 0 <= index < len(self._item_lines):
            return self._item_lines[index]
        return self._self_line or default


def create_line_loader() -> type[yaml.SafeLoader]:
    """Creates a custom PyYAML SafeLoader that preserves line numbers."""

    class ComposeSafeLoader(yaml.SafeLoader):
        pass

    def construct_mapping(loader: yaml.SafeLoader, node: yaml.MappingNode, deep: bool = False) -> LineDict:
        loader.flatten_mapping(node)
        mapping = LineDict()
        mapping._lines["__self__"] = node.start_mark.line + 1
        for key_node, value_node in node.value:
            key = loader.construct_object(key_node, deep=deep)
            val = loader.construct_object(value_node, deep=deep)
            mapping[key] = val
            if isinstance(key, str):
                mapping._lines[key] = key_node.start_mark.line + 1
        return mapping

    def construct_sequence(loader: yaml.SafeLoader, node: yaml.SequenceNode, deep: bool = False) -> LineList:
        seq = LineList()
        seq._self_line = node.start_mark.line + 1
        for item_node in node.value:
            val = loader.construct_object(item_node, deep=deep)
            seq.append(val)
            seq._item_lines.append(item_node.start_mark.line + 1)
        return seq

    ComposeSafeLoader.add_constructor(
        yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG,
        construct_mapping,
    )
    ComposeSafeLoader.add_constructor(
        yaml.resolver.BaseResolver.DEFAULT_SEQUENCE_TAG,
        construct_sequence,
    )
    return ComposeSafeLoader


DIRECTIVE_REGEX = re.compile(
    r"#\s*(?:docker-compose-validator|dc-validator)\s*:\s*(?:disable|ignore)\s*=\s*([A-Za-z0-9_,\s]+)",
    re.IGNORECASE,
)


@dataclass
class ParsedComposeFile:
    """Represents a parsed docker-compose file with metadata."""
    file_path: str
    content: str
    raw_lines: List[str]
    data: Optional[Union[Dict[str, Any], LineDict]] = None
    is_valid_yaml: bool = True
    error_message: Optional[str] = None
    error_line: Optional[int] = None
    error_column: Optional[int] = None
    file_ignores: Set[str] = field(default_factory=set)
    line_ignores: Dict[int, Set[str]] = field(default_factory=dict)

    @property
    def services(self) -> Dict[str, Any]:
        """Returns the services mapping if present, else empty dict."""
        if isinstance(self.data, dict):
            services = self.data.get("services")
            if isinstance(services, dict):
                return services
        return {}

    def get_service_line(self, service_name: str) -> Optional[int]:
        """Gets line number for a given service."""
        if isinstance(self.data, LineDict):
            services = self.data.get("services")
            if isinstance(services, LineDict):
                return services.get_line(service_name)
        return None

    def get_service_field_line(self, service_name: str, field_name: str) -> Optional[int]:
        """Gets line number for a specific field in a service."""
        if isinstance(self.data, LineDict):
            services = self.data.get("services")
            if isinstance(services, dict):
                svc_dict = services.get(service_name)
                if isinstance(svc_dict, LineDict):
                    return svc_dict.get_line(field_name)
                elif isinstance(svc_dict, dict):
                    # fallback to service declaration line
                    return self.get_service_line(service_name)
        return self.get_service_line(service_name)

    def is_rule_ignored(self, rule_id: str, line_number: Optional[int] = None) -> bool:
        """Checks if a rule is ignored globally or on a specific line."""
        norm_rule = rule_id.upper()
        if "ALL" in self.file_ignores or norm_rule in self.file_ignores:
            return True
        if line_number is not None:
            # Check the line itself
            if norm_rule in self.line_ignores.get(line_number, set()):
                return True
            # Also check the preceding line (comment line directly above)
            if norm_rule in self.line_ignores.get(line_number - 1, set()):
                return True
        return False


    def get_service_names(self) -> List[str]:
        """Returns list of defined service names in the compose file."""
        return list(self.services.keys())


    def get_service_ports(self, service_name: str) -> List[Any]:
        """Returns exposed ports list for a specified service."""
        svc = self.services.get(service_name)
        if isinstance(svc, dict):
            ports = svc.get("ports", [])
            return ports if isinstance(ports, list) else [ports]
        return []


    def get_service_environment(self, service_name: str) -> Any:
        """Returns declared environment variables dictionary or list for a service."""
        svc = self.services.get(service_name)
        if isinstance(svc, dict):
            return svc.get("environment", {})
        return {}


class ComposeParser:
    """Parser for docker-compose configuration files."""

    @classmethod
    def parse_file(cls, file_path: Union[str, Path]) -> ParsedComposeFile:
        """Parses a compose file from disk."""
        path_obj = Path(file_path).resolve()
        if not path_obj.exists():
            return ParsedComposeFile(
                file_path=str(path_obj),
                content="",
                raw_lines=[],
                data=None,
                is_valid_yaml=False,
                error_message=f"File not found: {path_obj}",
            )

        try:
            content = path_obj.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            try:
                content = path_obj.read_text(encoding="latin-1")
            except Exception as e:
                return ParsedComposeFile(
                    file_path=str(path_obj),
                    content="",
                    raw_lines=[],
                    data=None,
                    is_valid_yaml=False,
                    error_message=f"Failed to read file: {e}",
                )
        except Exception as e:
            return ParsedComposeFile(
                file_path=str(path_obj),
                content="",
                raw_lines=[],
                data=None,
                is_valid_yaml=False,
                error_message=f"Failed to read file: {e}",
            )

        return cls.parse_string(content, file_path=str(path_obj))

    @classmethod
    def parse_string(cls, content: str, file_path: str = "<inline>") -> ParsedComposeFile:
        """Parses compose YAML content string."""
        raw_lines = content.splitlines()
        file_ignores: Set[str] = set()
        line_ignores: Dict[int, Set[str]] = {}

        # Scan for ignore directives
        for idx, line in enumerate(raw_lines, start=1):
            match = DIRECTIVE_REGEX.search(line)
            if match:
                rules_str = match.group(1)
                rules = {r.strip().upper() for r in rules_str.split(",") if r.strip()}
                # If directive is in the first 5 lines and line has no YAML key, treat as file-wide
                stripped = line.strip()
                if idx <= 5 and (stripped.startswith("#") or not stripped.replace(" ", "").endswith(":")):
                    file_ignores.update(rules)
                line_ignores.setdefault(idx, set()).update(rules)

        if not content.strip():
            return ParsedComposeFile(
                file_path=file_path,
                content=content,
                raw_lines=raw_lines,
                data=None,
                is_valid_yaml=False,
                error_message="Compose file is empty.",
                file_ignores=file_ignores,
                line_ignores=line_ignores,
            )

        loader_cls = create_line_loader()
        try:
            data = yaml.load(content, Loader=loader_cls)
        except yaml.YAMLError as exc:
            err_line = None
            err_col = None
            if hasattr(exc, "problem_mark") and exc.problem_mark is not None:
                err_line = exc.problem_mark.line + 1
                err_col = exc.problem_mark.column + 1
            return ParsedComposeFile(
                file_path=file_path,
                content=content,
                raw_lines=raw_lines,
                data=None,
                is_valid_yaml=False,
                error_message=str(exc),
                error_line=err_line,
                error_column=err_col,
                file_ignores=file_ignores,
                line_ignores=line_ignores,
            )

        return ParsedComposeFile(
            file_path=file_path,
            content=content,
            raw_lines=raw_lines,
            data=data,
            is_valid_yaml=True,
            error_message=None,
            file_ignores=file_ignores,
            line_ignores=line_ignores,
        )
