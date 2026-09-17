#!/usr/bin/env python3
"""Build an atomic, allowlist-only public export with fresh history."""

from __future__ import annotations

import argparse
import hashlib
import os
import shutil
import subprocess
import tempfile
from pathlib import Path, PurePosixPath
from typing import Any, Mapping, Sequence

import yaml

from check_public_tree import (
    FULL_SHA_PATTERN,
    SHA256_PATTERN,
    check_export_tree,
    load_manifest,
    validate_manifest,
)


ALLOWED_GIT_FILE_MODES = {"100644", "100755"}


class ExportError(RuntimeError):
    """Raised when an export cannot be proven safe."""


def _format_errors(errors: Sequence[str]) -> str:
    return "\n".join(f"- {error}" for error in errors)


def _git_run(repo_root: Path, *arguments: str) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(
        ["git", *arguments],
        cwd=repo_root,
        check=False,
        capture_output=True,
    )


def _git_output(repo_root: Path, *arguments: str) -> str:
    completed = _git_run(repo_root, *arguments)
    if completed.returncode != 0:
        detail = completed.stderr.decode("utf-8", errors="replace").strip() or "unknown Git error"
        raise ExportError(f"Git command failed: {detail}")
    return completed.stdout.decode("utf-8", errors="replace").strip()


def _git_bytes(repo_root: Path, *arguments: str) -> bytes:
    completed = _git_run(repo_root, *arguments)
    if completed.returncode != 0:
        detail = completed.stderr.decode("utf-8", errors="replace").strip() or "unknown Git error"
        raise ExportError(f"Git command failed: {detail}")
    return completed.stdout


def _git_is_ancestor(repo_root: Path, ancestor: str, descendant: str) -> bool:
    completed = _git_run(repo_root, "merge-base", "--is-ancestor", ancestor, descendant)
    if completed.returncode == 0:
        return True
    if completed.returncode == 1:
        return False
    detail = completed.stderr.decode("utf-8", errors="replace").strip() or "unknown Git ancestry error"
    raise ExportError(f"Git ancestry check failed: {detail}")


def _git_commit_exists(repo_root: Path, commit: str) -> bool:
    return _git_run(repo_root, "cat-file", "-e", f"{commit}^{{commit}}").returncode == 0


def resolve_export_commit(manifest: Mapping[str, Any]) -> str:
    source = manifest.get("source")
    if not isinstance(source, Mapping):
        raise ExportError("manifest source is missing")
    export_commit = source.get("export_commit")
    if not isinstance(export_commit, str) or not FULL_SHA_PATTERN.fullmatch(export_commit):
        raise ExportError("manifest source.export_commit must be a full Git commit ID")
    return export_commit


def verify_release_source(repo_root: Path, manifest: Mapping[str, Any]) -> str:
    source = manifest.get("source")
    if not isinstance(source, Mapping):
        raise ExportError("manifest source is missing")

    export_commit = resolve_export_commit(manifest)
    if not _git_commit_exists(repo_root, export_commit):
        raise ExportError(f"export commit does not exist in source repository: {export_commit}")

    baseline_commit = source.get("baseline_commit")
    if not isinstance(baseline_commit, str) or not FULL_SHA_PATTERN.fullmatch(baseline_commit):
        raise ExportError("manifest source.baseline_commit must be a full Git commit ID")
    if not _git_commit_exists(repo_root, baseline_commit):
        raise ExportError(f"baseline commit does not exist in source repository: {baseline_commit}")
    if not _git_is_ancestor(repo_root, baseline_commit, export_commit):
        raise ExportError(f"export commit does not descend from the approved baseline: {baseline_commit}")

    excluded_ancestors = source.get("excluded_ancestor_commits")
    if not isinstance(excluded_ancestors, list) or not excluded_ancestors:
        raise ExportError("manifest source.excluded_ancestor_commits must be a non-empty list")
    for excluded_ancestor in excluded_ancestors:
        if not isinstance(excluded_ancestor, Mapping):
            raise ExportError("manifest excluded ancestor entries must be mappings")
        excluded_commit = str(excluded_ancestor.get("commit"))
        excluded_product = str(excluded_ancestor.get("product"))
        if not _git_commit_exists(repo_root, excluded_commit):
            continue
        if _git_is_ancestor(repo_root, excluded_commit, export_commit):
            raise ExportError(f"source commit descends from excluded product {excluded_product}: {excluded_commit}")
    return export_commit


def _staging_destination(staging_root: Path, entry: Mapping[str, Any]) -> Path:
    destination_relative = PurePosixPath(str(entry["destination"]))
    return staging_root.joinpath(*destination_relative.parts)


def _verify_worktree_source_file(source_root: Path, source_path: Path, entry: Mapping[str, Any]) -> None:
    if source_path.is_symlink():
        raise ExportError(f"allowlisted source is a symlink: {entry['source']}")
    if not source_path.is_file():
        raise ExportError(f"allowlisted source file is missing: {entry['source']}")

    resolved_root = source_root.resolve()
    resolved_source = source_path.resolve(strict=True)
    if resolved_root != resolved_source and resolved_root not in resolved_source.parents:
        raise ExportError(f"allowlisted source escapes the source root: {entry['source']}")

    relative_parts = PurePosixPath(str(entry["source"])).parts
    for depth in range(1, len(relative_parts)):
        ancestor = source_root.joinpath(*relative_parts[:depth])
        if ancestor.is_symlink():
            raise ExportError(f"allowlisted source traverses a symlink: {entry['source']}")

    expected_hash = entry.get("sha256")
    if isinstance(expected_hash, str) and SHA256_PATTERN.fullmatch(expected_hash):
        from check_public_tree import _sha256

        actual_hash = _sha256(source_path)
        if actual_hash != expected_hash:
            raise ExportError(
                f"source hash mismatch for {entry['source']}: expected {expected_hash}, got {actual_hash}"
            )


def _read_git_source_blob(repo_root: Path, commit: str, entry: Mapping[str, Any]) -> bytes:
    source_relative = str(entry["source"])
    listing = _git_output(repo_root, "ls-tree", commit, "--", source_relative)
    if not listing:
        raise ExportError(f"allowlisted source file is missing from commit {commit}: {source_relative}")

    metadata = listing.split("\t", 1)[0].split()
    if len(metadata) < 2:
        raise ExportError(f"unable to inspect Git tree entry: {source_relative}")
    mode, object_type = metadata[0], metadata[1]
    if mode == "120000":
        raise ExportError(f"allowlisted source is a symlink in commit {commit}: {source_relative}")
    if object_type != "blob" or mode not in ALLOWED_GIT_FILE_MODES:
        raise ExportError(f"allowlisted source is not a regular file in commit {commit}: {source_relative}")

    blob = _git_bytes(repo_root, "cat-file", "blob", f"{commit}:{source_relative}")
    expected_hash = entry.get("sha256")
    if isinstance(expected_hash, str) and SHA256_PATTERN.fullmatch(expected_hash):
        actual_hash = hashlib.sha256(blob).hexdigest()
        if actual_hash != expected_hash:
            raise ExportError(
                f"source hash mismatch for {source_relative}: expected {expected_hash}, got {actual_hash}"
            )
    return blob


def build_export(
    source_root: Path,
    output_root: Path,
    manifest: Mapping[str, Any],
    *,
    release: bool,
    verify_git: bool = True,
    from_commit: str | None = None,
) -> Path:
    manifest_result = validate_manifest(manifest, release=release)
    if manifest_result.errors:
        raise ExportError(f"manifest validation failed:\n{_format_errors(manifest_result.errors)}")

    source_root = source_root.absolute()
    if source_root.is_symlink():
        raise ExportError("source root must not be a symlink")
    source_root = source_root.resolve()
    output_root = output_root.resolve()
    if not source_root.is_dir():
        raise ExportError("source root must be a real directory")
    if output_root.exists():
        raise ExportError(f"output path already exists: {output_root}")
    if source_root == output_root or source_root in output_root.parents:
        raise ExportError("output path must be outside the source tree")

    export_commit: str | None = None
    if release:
        if from_commit is not None and from_commit != resolve_export_commit(manifest):
            raise ExportError("release exports must use manifest source.export_commit")
        export_commit = verify_release_source(source_root, manifest) if verify_git else resolve_export_commit(manifest)
    elif from_commit is not None:
        if not FULL_SHA_PATTERN.fullmatch(from_commit):
            raise ExportError("--from-commit must be a full lowercase Git commit ID")
        if not _git_commit_exists(source_root, from_commit):
            raise ExportError(f"export commit does not exist in source repository: {from_commit}")
        export_commit = from_commit

    output_root.parent.mkdir(parents=True, exist_ok=True)
    staging_root = Path(tempfile.mkdtemp(prefix=f".{output_root.name}.staging-", dir=output_root.parent))
    try:
        entries = manifest.get("files")
        assert isinstance(entries, list)
        for entry in entries:
            assert isinstance(entry, Mapping)
            destination_path = _staging_destination(staging_root, entry)
            destination_path.parent.mkdir(parents=True, exist_ok=True)
            if export_commit is None:
                source_relative = PurePosixPath(str(entry["source"]))
                source_path = source_root.joinpath(*source_relative.parts)
                _verify_worktree_source_file(source_root, source_path, entry)
                shutil.copyfile(source_path, destination_path)
            else:
                destination_path.write_bytes(_read_git_source_blob(source_root, export_commit, entry))
            os.chmod(destination_path, 0o644)

        tree_result = check_export_tree(staging_root, manifest, release=release)
        if tree_result.errors:
            raise ExportError(f"staged export validation failed:\n{_format_errors(tree_result.errors)}")

        if output_root.exists():
            raise ExportError(f"output path appeared during export: {output_root}")
        staging_root.replace(output_root)
        return output_root
    finally:
        if staging_root.exists():
            shutil.rmtree(staging_root)


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, default=Path("PUBLIC_EXPORT_MANIFEST.yml"))
    parser.add_argument("--source-root", type=Path, default=Path("."))
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument(
        "--draft",
        action="store_true",
        help="allow pending review metadata and export from the working tree by default",
    )
    parser.add_argument(
        "--from-commit",
        help="draft-mode override: export blobs from this pinned Git commit instead of the working tree",
    )
    args = parser.parse_args(argv)

    try:
        manifest = load_manifest(args.manifest)
        output_root = build_export(
            args.source_root,
            args.output,
            manifest,
            release=not args.draft,
            verify_git=not args.draft,
            from_commit=args.from_commit,
        )
    except (ExportError, OSError, ValueError, yaml.YAMLError) as exc:
        print(f"ERROR: {exc}")
        return 1

    mode = "draft" if args.draft else "release"
    print(f"Built {mode} public export at {output_root}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
