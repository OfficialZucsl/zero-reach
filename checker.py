#!/usr/bin/env python3
"""
zero-reach: Lightweight dependency reachability checker.

Scans a local directory/container for common dependency declaration files,
checks them against a small mock vulnerability database, and simulates
whether vulnerable packages are actively reachable from the runtime environment.

This is a demonstration tool, not a replacement for a real SCA/runtime
security product.

Usage:
    python3 checker.py --target /path/to/environment

Examples:
    python3 checker.py --target .
    python3 checker.py --target /tmp/container-root
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional, Tuple
import xml.etree.ElementTree as ET


# Sentinel used when a Maven <version>${property}</version> reference cannot
# be resolved from the POM's <properties> block. The dependency is still
# recorded and reported rather than being silently dropped.
UNRESOLVED_VERSION = "[DYNAMIC/UNRESOLVED]"


# ---------------------------------------------------------------------------
# Mock vulnerability database
# ---------------------------------------------------------------------------

KNOWN_VULNERABILITIES: Dict[str, Dict[str, str]] = {
    "requests": {
        "range": "<2.20.0",
        "id": "ZRX-2026-0001",
        "description": "Simulated request parsing vulnerability.",
    },
    "lodash": {
        "range": "<4.17.21",
        "id": "ZRX-2026-0002",
        "description": "Simulated prototype pollution vulnerability.",
    },
    "log4j-core": {
        "range": "<2.17.0",
        "id": "ZRX-2026-0003",
        "description": "Simulated remote code execution vulnerability.",
    },
    "flask": {
        "range": "<2.3.0",
        "id": "ZRX-2026-0004",
        "description": "Simulated request handling vulnerability.",
    },
}


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------

@dataclass
class Dependency:
    """Represents a dependency discovered in a declaration file."""

    name: str
    version: str
    source_file: Path
    ecosystem: str


@dataclass
class Finding:
    """Represents a vulnerability discovered during the scan."""

    dependency: Dependency
    vulnerability_id: str
    vulnerable_range: str
    description: str
    active: bool = False
    runtime_evidence: Optional[str] = None


# ---------------------------------------------------------------------------
# Version handling
# ---------------------------------------------------------------------------

def parse_version(version: str) -> Tuple[int, int, int]:
    """Convert a simple semantic version into a comparable tuple."""
    if version == UNRESOLVED_VERSION:
        raise ValueError(f"Unresolved version cannot be parsed: {version}")

    match = re.search(r"(\d+)(?:\.(\d+))?(?:\.(\d+))?", version)

    if not match:
        raise ValueError(f"Unsupported version format: {version}")

    major = int(match.group(1))
    minor = int(match.group(2) or 0)
    patch = int(match.group(3) or 0)

    return major, minor, patch


def version_matches(version: str, version_range: str) -> bool:
    """Determine whether a version falls inside a small supported range syntax."""
    try:
        current = parse_version(version)
    except ValueError:
        return False

    for expression in version_range.split(","):
        expression = expression.strip()

        operators = (">=", "<=", ">", "<", "=")
        operator = next(
            (op for op in operators if expression.startswith(op)),
            None,
        )

        if operator is None:
            return False

        required = expression[len(operator):].strip()

        try:
            required_version = parse_version(required)
        except ValueError:
            return False

        if operator == ">=" and not (current >= required_version):
            return False

        if operator == "<=" and not (current <= required_version):
            return False

        if operator == ">" and not (current > required_version):
            return False

        if operator == "<" and not (current < required_version):
            return False

        if operator == "=" and not (current == required_version):
            return False

    return True


# ---------------------------------------------------------------------------
# Dependency file parsers
# ---------------------------------------------------------------------------

def parse_requirements(path: Path) -> List[Dependency]:
    """Parse Python requirements.txt files."""
    dependencies: List[Dependency] = []

    try:
        for raw_line in path.read_text(
            encoding="utf-8",
            errors="ignore",
        ).splitlines():
            line = raw_line.strip()

            if not line or line.startswith("#"):
                continue

            line = line.split(";", 1)[0].strip()

            match = re.match(
                r"^([A-Za-z0-9_.-]+)\s*==\s*([0-9][A-Za-z0-9.+-]*)$",
                line,
            )

            if match:
                dependencies.append(
                    Dependency(
                        name=match.group(1).lower(),
                        version=match.group(2),
                        source_file=path,
                        ecosystem="python",
                    )
                )

    except OSError as exc:
        print(f"[ERROR] Could not read {path}: {exc}", file=sys.stderr)

    return dependencies


def parse_package_json(path: Path) -> List[Dependency]:
    """Parse dependencies/devDependencies from a Node package.json file."""
    dependencies: List[Dependency] = []

    try:
        data = json.loads(path.read_text(encoding="utf-8"))

        sections = (
            ("dependencies", "production"),
            ("devDependencies", "development"),
        )

        for section_name, environment in sections:
            packages = data.get(section_name, {})

            if not isinstance(packages, dict):
                continue

            for package_name, declared_version in packages.items():
                if not isinstance(declared_version, str):
                    continue

                match = re.search(
                    r"(\d+\.\d+\.\d+)",
                    declared_version,
                )

                if not match:
                    continue

                dependencies.append(
                    Dependency(
                        name=package_name.lower(),
                        version=match.group(1),
                        source_file=path,
                        ecosystem=f"node/{environment}",
                    )
                )

    except (OSError, json.JSONDecodeError) as exc:
        print(f"[ERROR] Could not parse {path}: {exc}", file=sys.stderr)

    return dependencies


def parse_pom_xml(path: Path) -> List[Dependency]:
    """Parse Maven pom.xml dependencies, resolving local properties or falling back safely."""
    dependencies: List[Dependency] = []

    try:
        root = ET.parse(path).getroot()

        # Extract local properties block if present
        properties: Dict[str, str] = {}
        for elem in root.iter():
            if elem.tag.rsplit("}", 1)[-1] == "properties":
                for prop in elem:
                    properties[prop.tag.rsplit("}", 1)[-1]] = (prop.text or "").strip()

        for dependency in root.iter():
            if dependency.tag.rsplit("}", 1)[-1] != "dependency":
                continue

            values: Dict[str, str] = {}

            for child in dependency:
                tag = child.tag.rsplit("}", 1)[-1]
                text = (child.text or "").strip()
                values[tag] = text

            artifact = values.get("artifactId")
            version = values.get("version")

            if not artifact or not version:
                continue

            version_str = version.strip()

            # Fix 1: Handle property-based versions like ${spring.version}
            prop_match = re.match(r"^\${([^}]+)}$", version_str)
            if prop_match:
                prop_name = prop_match.group(1)
                version_str = properties.get(prop_name, UNRESOLVED_VERSION)

            if version_str == UNRESOLVED_VERSION:
                normalized_version = UNRESOLVED_VERSION
            else:
                match = re.search(r"(\d+\.\d+(?:\.\d+)?)", version_str)
                if match:
                    normalized_version = match.group(1)
                else:
                    normalized_version = UNRESOLVED_VERSION

            dependencies.append(
                Dependency(
                    name=artifact.lower(),
                    version=normalized_version,
                    source_file=path,
                    ecosystem="maven",
                )
            )

    except (OSError, ET.ParseError) as exc:
        print(f"[ERROR] Could not parse {path}: {exc}", file=sys.stderr)

    return dependencies


# ---------------------------------------------------------------------------
# File discovery
# ---------------------------------------------------------------------------

def find_dependency_files(target: Path) -> List[Path]:
    """Recursively discover supported dependency declaration files."""
    supported_names = {
        "requirements.txt",
        "package.json",
        "pom.xml",
    }

    if target.is_file():
        return [target] if target.name in supported_names else []

    files: List[Path] = []

    for root, dirs, filenames in os.walk(target):
        dirs[:] = [
            directory
            for directory in dirs
            if directory not in {
                ".git",
                "__pycache__",
                "node_modules",
                ".cache",
                "proc",
                "sys",
                "dev",
            }
        ]

        for filename in filenames:
            if filename in supported_names:
                files.append(Path(root) / filename)

    return files


def collect_dependencies(target: Path) -> List[Dependency]:
    """Parse all supported dependency files under the target."""
    all_dependencies: List[Dependency] = []

    dependency_files = find_dependency_files(target)

    for path in dependency_files:
        if path.name == "requirements.txt":
            all_dependencies.extend(parse_requirements(path))

        elif path.name == "package.json":
            all_dependencies.extend(parse_package_json(path))

        elif path.name == "pom.xml":
            all_dependencies.extend(parse_pom_xml(path))

    return all_dependencies


# ---------------------------------------------------------------------------
# Runtime / reachability simulation
# ---------------------------------------------------------------------------

def dependency_runtime_candidates(scope_dir: Path, package_name: str) -> List[str]:
    """Look for evidence that a package is part of a runtime environment within a scoped directory."""
    candidates: List[str] = []
    package_token = package_name.lower().replace("_", "-")

    runtime_directories = {
        "site-packages",
        "dist-packages",
        "node_modules",
        "lib",
        "lib64",
        "usr",
        "opt",
    }

    marker_names = {
        "runtime.loaded",
        "runtime_active.txt",
        ".zero-reach-active",
    }

    if scope_dir.is_file():
        scope_dir = scope_dir.parent

    for root, dirs, files in os.walk(scope_dir):
        dirs[:] = [
            d for d in dirs
            if d not in {
                ".git",
                "__pycache__",
                "proc",
                "sys",
                "dev",
            }
        ]

        current = Path(root)
        parts_lower = {part.lower() for part in current.parts}
        is_runtime_location = bool(parts_lower & runtime_directories) or (current == scope_dir)

        if not is_runtime_location:
            continue

        for filename in files:
            filename_lower = filename.lower()

            if package_token in filename_lower:
                candidates.append(str(current / filename))

        for marker in marker_names:
            if marker in files and package_token in str(current).lower():
                candidates.append(str(current / marker))

    return candidates


def is_dependency_active(target: Path, dependency: Dependency) -> Tuple[bool, Optional[str]]:
    """Simulate whether a vulnerable dependency is reachable, strictly scoped to its local project directory."""
    # Fix 2: Scope search strictly to the local project directory/submodule containing the manifest
    scope_dir = dependency.source_file.parent
    evidence = dependency_runtime_candidates(scope_dir, dependency.name)

    if evidence:
        return True, evidence[0]

    marker_paths = [
        path
        for path in scope_dir.rglob(".zero-reach-runtime")
        if path.is_file()
    ]

    package_name = dependency.name.lower()

    for marker_path in marker_paths:
        try:
            contents = marker_path.read_text(
                encoding="utf-8",
                errors="ignore",
            ).lower()

            if package_name in contents:
                return True, str(marker_path)

        except OSError:
            continue

    return False, None


# ---------------------------------------------------------------------------
# Vulnerability analysis
# ---------------------------------------------------------------------------

def analyze_dependencies(
    dependencies: List[Dependency],
    target: Path,
) -> List[Finding]:
    """Compare discovered dependencies against the mock vulnerability DB."""
    findings: List[Finding] = []

    for dependency in dependencies:
        vulnerability = KNOWN_VULNERABILITIES.get(
            dependency.name.lower()
        )

        if not vulnerability:
            continue

        if not version_matches(
            dependency.version,
            vulnerability["range"],
        ):
            continue

        active, evidence = is_dependency_active(
            target,
            dependency,
        )

        findings.append(
            Finding(
                dependency=dependency,
                vulnerability_id=vulnerability["id"],
                vulnerable_range=vulnerability["range"],
                description=vulnerability["description"],
                active=active,
                runtime_evidence=evidence,
            )
        )

    return findings


# ---------------------------------------------------------------------------
# Terminal reporting
# ---------------------------------------------------------------------------

def print_report(
    target: Path,
    dependencies: List[Dependency],
    findings: List[Finding],
) -> None:
    """Render a clean human-readable scan report."""
    print()
    print("=" * 72)
    print("zero-reach :: Dependency Reachability Scanner")
    print("=" * 72)
    print(f"Target:       {target}")
    print(f"Dependencies: {len(dependencies)}")
    print(f"Findings:     {len(findings)}")
    print()

    if not findings:
        print("[SECURE] No known vulnerable dependencies were found.")
        print("=" * 72)
        return

    for finding in findings:
        dependency = finding.dependency

        if finding.active:
            status = "[VULNERABLE & ACTIVE]"
        else:
            status = "[VULNERABLE BUT UNREACHABLE]"

        print(status)
        print(f"  Package:        {dependency.name}")
        print(f"  Version:        {dependency.version}")
        print(f"  Ecosystem:      {dependency.ecosystem}")
        print(f"  Declaration:    {dependency.source_file}")
        print(f"  Vulnerability:  {finding.vulnerability_id}")
        print(f"  Affected range: {finding.vulnerable_range}")
        print(f"  Description:    {finding.description}")

        if finding.active:
            print(f"  Runtime evidence:{finding.runtime_evidence}")
            print(
                "  Interpretation:  vulnerable code appears reachable "
                "from a simulated runtime path."
            )
        else:
            print(
                "  Interpretation:  vulnerable package exists in dependency "
                "metadata but no runtime evidence was found."
            )

        print("-" * 72)

    print("=" * 72)

    active_count = sum(finding.active for finding in findings)
    unreachable_count = len(findings) - active_count

    print(
        f"Summary: {active_count} active, "
        f"{unreachable_count} vulnerable-but-unreachable."
    )
    print("=" * 72)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    """Create the command-line argument parser."""
    parser = argparse.ArgumentParser(
        prog="checker.py",
        description=(
            "zero-reach: scan a local environment/container directory "
            "for vulnerable dependencies and simulate runtime reachability."
        ),
    )

    parser.add_argument(
        "--target",
        required=True,
        help=(
            "Path to a file or directory representing the environment "
            "or container filesystem to scan."
        ),
    )

    return parser


def main() -> int:
    """Program entry point."""
    parser = build_parser()
    args = parser.parse_args()

    target = Path(args.target).expanduser().resolve()

    if not target.exists():
        print(
            f"[ERROR] Target does not exist: {target}",
            file=sys.stderr,
        )
        return 2

    if not os.access(target, os.R_OK):
        print(
            f"[ERROR] Target is not readable: {target}",
            file=sys.stderr,
        )
        return 2

    try:
        dependencies = collect_dependencies(target)
        findings = analyze_dependencies(
            dependencies,
            target if target.is_dir() else target.parent,
        )

        print_report(
            target,
            dependencies,
            findings,
        )

    except KeyboardInterrupt:
        print("\n[ERROR] Scan interrupted by user.", file=sys.stderr)
        return 130

    except PermissionError as exc:
        print(
            f"[ERROR] Permission denied while scanning: {exc}",
            file=sys.stderr,
        )
        return 3

    except OSError as exc:
        print(
            f"[ERROR] Filesystem error: {exc}",
            file=sys.stderr,
        )
        return 3

    except Exception as exc:
        print(
            f"[ERROR] Unexpected scanner failure: {exc}",
            file=sys.stderr,
        )
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
