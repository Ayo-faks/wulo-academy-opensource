#!/usr/bin/env python3
"""Validate a candidate public export against its exact allowlist."""

from __future__ import annotations

import argparse
import fnmatch
import hashlib
import re
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
from typing import Any, Iterable, Mapping, Sequence

import yaml


FULL_SHA_PATTERN = re.compile(r"^[0-9a-f]{40}$")
SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")
EMAIL_PATTERN = re.compile(r"^[^\s@]+@[^\s@]+\.[^\s@]+$")
APPROVED_RIGHTS = {
    "approved",
    "company-owned",
    "generated-approved",
    "third-party-approved",
    "upstream-mit",
}
PENDING_VALUES = {"", "pending", "unassigned", "tbd", "todo"}
FORBIDDEN_COMPONENTS = {
    ".agentops",
    ".azure",
    ".deepeval",
    ".git",
    ".local-logs",
    ".private",
    ".pytest_cache",
    ".recovery",
    ".venv",
    "__pycache__",
    "backups",
    "node_modules",
    "playwright-report",
    "test-results",
}
FORBIDDEN_FILENAMES = {
    ".gitmodules",
    "id_dsa",
    "id_ed25519",
    "id_rsa",
    "known_hosts",
}
FORBIDDEN_SUFFIXES = {
    ".cer",
    ".crt",
    ".db",
    ".der",
    ".dump",
    ".jks",
    ".key",
    ".keystore",
    ".p12",
    ".pem",
    ".pfx",
    ".sqlite",
    ".sqlite3",
}
FORBIDDEN_ARCHIVE_ENDINGS = (
    ".7z",
    ".gz",
    ".rar",
    ".tar",
    ".tar.gz",
    ".tgz",
    ".zip",
)
ALLOWED_ENV_EXAMPLES = {".env.example", ".env.azure.example"}
LFS_POINTER_PREFIX = b"version https://git-lfs.github.com/spec/v1\n"


@dataclass
class CheckResult:
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return not self.errors

    def extend(self, other: "CheckResult") -> None:
        self.errors.extend(other.errors)
        self.warnings.extend(other.warnings)


def load_manifest(path: Path) -> dict[str, Any]:
    payload = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError("manifest must contain a YAML mapping")
    return payload


def _is_safe_relative_path(value: object) -> bool:
    if not isinstance(value, str) or not value or "\\" in value or "\x00" in value:
        return False
    path = PurePosixPath(value)
    return not path.is_absolute() and value == path.as_posix() and "." not in path.parts and ".." not in path.parts


def _pending(value: object) -> bool:
    return not isinstance(value, str) or value.strip().lower() in PENDING_VALUES


def _manifest_files(manifest: Mapping[str, Any]) -> list[Mapping[str, Any]]:
    files = manifest.get("files")
    if not isinstance(files, list):
        return []
    return [entry for entry in files if isinstance(entry, Mapping)]


def validate_manifest(manifest: Mapping[str, Any], *, release: bool = False) -> CheckResult:
    result = CheckResult()
    if manifest.get("schema_version") != 1:
        result.errors.append("manifest schema_version must be 1")

    status = manifest.get("status")
    if status not in {"draft", "approved"}:
        result.errors.append("manifest status must be draft or approved")
    if release and status != "approved":
        result.errors.append("release check requires manifest status approved")

    project = manifest.get("project")
    if not isinstance(project, Mapping):
        result.errors.append("manifest project must be a mapping")
    else:
        for field_name in ("name", "destination_repository", "product_scope", "release_posture"):
            if _pending(project.get(field_name)):
                result.errors.append(f"project.{field_name} is required")

        legal_owner = project.get("legal_owner")
        if not isinstance(legal_owner, Mapping):
            result.errors.append("project.legal_owner must be a mapping")
        else:
            if _pending(legal_owner.get("name")):
                result.errors.append("project.legal_owner.name is required")
            contact_email = legal_owner.get("contact_email")
            if not isinstance(contact_email, str) or not EMAIL_PATTERN.fullmatch(contact_email):
                result.errors.append("project.legal_owner.contact_email must be a valid email address")

        excluded_products = project.get("excluded_products")
        if not isinstance(excluded_products, list) or not excluded_products:
            result.errors.append("project.excluded_products must be a non-empty list")
        else:
            excluded_ids: set[str] = set()
            for index, excluded_product in enumerate(excluded_products):
                label = f"project.excluded_products[{index}]"
                if not isinstance(excluded_product, Mapping):
                    result.errors.append(f"{label} must be a mapping")
                    continue
                product_id = excluded_product.get("id")
                if _pending(product_id):
                    result.errors.append(f"{label}.id is required")
                elif product_id in excluded_ids:
                    result.errors.append(f"duplicate excluded product id: {product_id}")
                else:
                    excluded_ids.add(product_id)
                if _pending(excluded_product.get("name")):
                    result.errors.append(f"{label}.name is required")
                deny_globs = excluded_product.get("deny_globs")
                if not isinstance(deny_globs, list) or not deny_globs:
                    result.errors.append(f"{label}.deny_globs must be a non-empty list")
                elif not all(isinstance(pattern, str) and pattern for pattern in deny_globs):
                    result.errors.append(f"{label}.deny_globs must contain non-empty strings")

    source = manifest.get("source")
    if not isinstance(source, Mapping):
        result.errors.append("manifest source must be a mapping")
    else:
        for field_name in ("baseline_commit", "upstream_merge_base"):
            value = source.get(field_name)
            if not isinstance(value, str) or not FULL_SHA_PATTERN.fullmatch(value):
                result.errors.append(f"source.{field_name} must be a full lowercase Git commit ID")

        export_commit = source.get("export_commit")
        if release:
            if not isinstance(export_commit, str) or not FULL_SHA_PATTERN.fullmatch(export_commit):
                result.errors.append("source.export_commit must be a full lowercase Git commit ID")
        elif not isinstance(export_commit, str) or not FULL_SHA_PATTERN.fullmatch(export_commit):
            result.warnings.append("source.export_commit is pending")

        if source.get("history_strategy") != "fresh":
            result.errors.append("source.history_strategy must be fresh")
        if _pending(source.get("branch")):
            result.errors.append("source.branch is required")
        project_scope = project.get("product_scope") if isinstance(project, Mapping) else None
        if source.get("product_scope") != project_scope:
            result.errors.append("source.product_scope must match project.product_scope")

        excluded_ancestors = source.get("excluded_ancestor_commits")
        if not isinstance(excluded_ancestors, list) or not excluded_ancestors:
            result.errors.append("source.excluded_ancestor_commits must be a non-empty list")
        else:
            excluded_commits: set[str] = set()
            for index, excluded_ancestor in enumerate(excluded_ancestors):
                label = f"source.excluded_ancestor_commits[{index}]"
                if not isinstance(excluded_ancestor, Mapping):
                    result.errors.append(f"{label} must be a mapping")
                    continue
                commit = excluded_ancestor.get("commit")
                if not isinstance(commit, str) or not FULL_SHA_PATTERN.fullmatch(commit):
                    result.errors.append(f"{label}.commit must be a full lowercase Git commit ID")
                elif commit in excluded_commits:
                    result.errors.append(f"duplicate excluded ancestor commit: {commit}")
                else:
                    excluded_commits.add(commit)
                if _pending(excluded_ancestor.get("product")):
                    result.errors.append(f"{label}.product is required")

    files = manifest.get("files")
    if not isinstance(files, list) or not files:
        result.errors.append("manifest files must be a non-empty list")
        return result

    destinations: set[str] = set()
    sources: set[str] = set()
    for index, raw_entry in enumerate(files):
        label = f"files[{index}]"
        if not isinstance(raw_entry, Mapping):
            result.errors.append(f"{label} must be a mapping")
            continue

        source_path = raw_entry.get("source")
        destination = raw_entry.get("destination")
        if not _is_safe_relative_path(source_path):
            result.errors.append(f"{label}.source must be a normalized relative path")
        elif source_path in sources:
            result.errors.append(f"duplicate source path: {source_path}")
        else:
            sources.add(source_path)

        if not _is_safe_relative_path(destination):
            result.errors.append(f"{label}.destination must be a normalized relative path")
        elif destination in destinations:
            result.errors.append(f"duplicate destination path: {destination}")
        else:
            destinations.add(destination)

        category = raw_entry.get("category")
        if _pending(category):
            result.errors.append(f"{label}.category is required")

        origin = raw_entry.get("origin")
        if origin not in {"generated", "source-tree"}:
            result.errors.append(f"{label}.origin must be generated or source-tree")

        source_commit = raw_entry.get("source_commit")
        rights = raw_entry.get("rights")
        reviewer = raw_entry.get("reviewer")
        expected_hash = raw_entry.get("sha256")
        if release:
            if not isinstance(source_commit, str) or not FULL_SHA_PATTERN.fullmatch(source_commit):
                result.errors.append(f"{label}.source_commit must be a full Git commit ID")
            if rights not in APPROVED_RIGHTS:
                result.errors.append(f"{label}.rights is not approved")
            if _pending(reviewer):
                result.errors.append(f"{label}.reviewer is not assigned")
            if not isinstance(expected_hash, str) or not SHA256_PATTERN.fullmatch(expected_hash):
                result.errors.append(f"{label}.sha256 must be an approved file hash")
        else:
            if not isinstance(source_commit, str) or not FULL_SHA_PATTERN.fullmatch(source_commit):
                result.warnings.append(f"{label}.source_commit is pending")
            if rights not in APPROVED_RIGHTS:
                result.warnings.append(f"{label}.rights is pending")
            if _pending(reviewer):
                result.warnings.append(f"{label}.reviewer is pending")
            if not isinstance(expected_hash, str) or not SHA256_PATTERN.fullmatch(expected_hash):
                result.warnings.append(f"{label}.sha256 is pending")

    return result


def _additional_deny_globs(manifest: Mapping[str, Any]) -> list[str]:
    result: list[str] = []
    policy = manifest.get("policy")
    if isinstance(policy, Mapping):
        patterns = policy.get("deny_globs")
        if isinstance(patterns, list):
            result.extend(pattern.lower() for pattern in patterns if isinstance(pattern, str) and pattern)

    project = manifest.get("project")
    if isinstance(project, Mapping):
        excluded_products = project.get("excluded_products")
        if isinstance(excluded_products, list):
            for excluded_product in excluded_products:
                if not isinstance(excluded_product, Mapping):
                    continue
                patterns = excluded_product.get("deny_globs")
                if isinstance(patterns, list):
                    result.extend(pattern.lower() for pattern in patterns if isinstance(pattern, str) and pattern)
    return result


def _forbidden_reason(relative_path: str, deny_globs: Iterable[str]) -> str | None:
    normalized = relative_path.lower()
    path = PurePosixPath(normalized)
    if any(component in FORBIDDEN_COMPONENTS or component.startswith(".tmp") for component in path.parts):
        return "contains a forbidden directory"
    if path.name in FORBIDDEN_FILENAMES:
        return "uses a forbidden filename"
    if path.name.startswith(".env") and path.name not in ALLOWED_ENV_EXAMPLES:
        return "looks like an environment-secret file"
    if path.name.endswith(".env"):
        return "looks like an environment-secret file"
    if path.suffix in FORBIDDEN_SUFFIXES:
        return "uses a forbidden credential or database suffix"
    if normalized.endswith(FORBIDDEN_ARCHIVE_ENDINGS):
        return "uses a forbidden archive suffix"
    if any(fnmatch.fnmatchcase(normalized, pattern) for pattern in deny_globs):
        return "matches a manifest deny rule"
    return None


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _is_lfs_pointer(path: Path) -> bool:
    try:
        with path.open("rb") as stream:
            return stream.read(len(LFS_POINTER_PREFIX)) == LFS_POINTER_PREFIX
    except OSError:
        return False


def check_export_tree(root: Path, manifest: Mapping[str, Any], *, release: bool = False) -> CheckResult:
    result = validate_manifest(manifest, release=release)
    if not root.is_dir():
        result.errors.append(f"export root is not a directory: {root}")
        return result
    if root.is_symlink():
        result.errors.append("export root must not be a symlink")
        return result

    expected_entries = {
        str(entry["destination"]): entry
        for entry in _manifest_files(manifest)
        if _is_safe_relative_path(entry.get("destination"))
    }
    deny_globs = _additional_deny_globs(manifest)
    discovered_files: dict[str, Path] = {}

    for path in sorted(root.rglob("*")):
        relative_path = path.relative_to(root).as_posix()
        if path.is_symlink():
            result.errors.append(f"symlink is forbidden: {relative_path}")
            continue
        if not path.is_file():
            continue
        discovered_files[relative_path] = path

        reason = _forbidden_reason(relative_path, deny_globs)
        if reason:
            result.errors.append(f"forbidden path {relative_path}: {reason}")
        if relative_path not in expected_entries:
            result.errors.append(f"file is not allowlisted: {relative_path}")
        if _is_lfs_pointer(path):
            result.errors.append(f"Git LFS pointer is forbidden: {relative_path}")

    for destination, entry in expected_entries.items():
        path = discovered_files.get(destination)
        if path is None:
            result.errors.append(f"allowlisted file is missing: {destination}")
            continue
        expected_hash = entry.get("sha256")
        if isinstance(expected_hash, str) and SHA256_PATTERN.fullmatch(expected_hash):
            actual_hash = _sha256(path)
            if actual_hash != expected_hash:
                result.errors.append(f"hash mismatch for {destination}: expected {expected_hash}, got {actual_hash}")

    return result


def _print_result(result: CheckResult) -> None:
    for warning in result.warnings:
        print(f"WARN: {warning}")
    for error in result.errors:
        print(f"ERROR: {error}")
    if result.ok:
        print("Public export policy check passed.")
    else:
        print(f"Public export policy check failed with {len(result.errors)} error(s).")


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, default=Path("PUBLIC_EXPORT_MANIFEST.yml"))
    parser.add_argument("--root", type=Path, help="candidate export directory")
    parser.add_argument("--manifest-only", action="store_true", help="validate only manifest structure")
    parser.add_argument("--release", action="store_true", help="require all reviews and hashes to be approved")
    args = parser.parse_args(argv)

    if not args.manifest_only and args.root is None:
        parser.error("--root is required unless --manifest-only is used")

    try:
        manifest = load_manifest(args.manifest)
    except (OSError, ValueError, yaml.YAMLError) as exc:
        print(f"ERROR: unable to load manifest: {exc}")
        return 2

    if args.manifest_only:
        result = validate_manifest(manifest, release=args.release)
    else:
        result = check_export_tree(args.root, manifest, release=args.release)
    _print_result(result)
    return 0 if result.ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
