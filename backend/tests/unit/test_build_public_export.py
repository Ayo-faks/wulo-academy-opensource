"""Tests for the atomic allowlist-only public export builder."""

from __future__ import annotations

import hashlib
import importlib.util
import subprocess
import sys
from pathlib import Path

import pytest


SCRIPT_PATH = (Path(__file__).resolve().parents[3] / "scripts" / "build_public_export.py").resolve()


@pytest.fixture(scope="module")
def export_module():
    sys.path.insert(0, str(SCRIPT_PATH.parent))
    spec = importlib.util.spec_from_file_location("build_public_export", SCRIPT_PATH)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules["build_public_export"] = module
    spec.loader.exec_module(module)
    return module


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _sha256_bytes(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _git(repo_root: Path, *arguments: str) -> str:
    completed = subprocess.run(
        ["git", "-c", "user.name=Test Owner", "-c", "user.email=owner@example.test", *arguments],
        cwd=repo_root,
        check=True,
        capture_output=True,
        text=True,
    )
    return completed.stdout.strip()


def _git_commit_all(repo_root: Path, message: str) -> str:
    _git(repo_root, "add", "-A")
    _git(repo_root, "commit", "-q", "-m", message)
    return _git(repo_root, "rev-parse", "HEAD")


def _manifest(
    path: str,
    digest: str,
    *,
    status: str = "approved",
    baseline_commit: str = "1" * 40,
    export_commit: str = "4" * 40,
    excluded_commit: str = "3" * 40,
) -> dict:
    return {
        "schema_version": 1,
        "status": status,
        "project": {
            "name": "Wulo Academy",
            "destination_repository": "wulo-academy",
            "product_scope": "academy",
            "release_posture": "developer-preview",
            "legal_owner": {
                "name": "Test Owner",
                "contact_email": "owner@example.test",
            },
            "excluded_products": [
                {
                    "id": "restricted",
                    "name": "Restricted Product",
                    "deny_globs": ["backend/src/learning/restricted*"],
                }
            ],
        },
        "source": {
            "repository": "https://example.test/private-source",
            "branch": "main",
            "product_scope": "academy",
            "baseline_commit": baseline_commit,
            "export_commit": export_commit,
            "upstream_repository": "https://example.test/upstream",
            "upstream_merge_base": "2" * 40,
            "excluded_ancestor_commits": [
                {
                    "commit": excluded_commit,
                    "product": "restricted",
                }
            ],
            "history_strategy": "fresh",
        },
        "policy": {"deny_globs": ["private/**"]},
        "files": [
            {
                "source": path,
                "destination": path,
                "category": "test-fixture",
                "origin": "source-tree",
                "source_commit": baseline_commit,
                "rights": "company-owned",
                "reviewer": "Test Reviewer",
                "sha256": digest,
            }
        ],
    }


def test_build_copies_only_allowlisted_files(tmp_path: Path, export_module) -> None:
    source_root = tmp_path / "source"
    source_root.mkdir()
    allowed_path = source_root / "README.md"
    allowed_path.write_text("synthetic demo\n", encoding="utf-8")
    (source_root / ".env").write_text("TOKEN=must-not-cross\n", encoding="utf-8")
    output_root = tmp_path / "public"

    result = export_module.build_export(
        source_root,
        output_root,
        _manifest("README.md", _sha256(allowed_path)),
        release=False,
        verify_git=False,
    )

    assert result == output_root
    assert (output_root / "README.md").read_text(encoding="utf-8") == "synthetic demo\n"
    assert not (output_root / ".env").exists()


def test_hash_mismatch_leaves_no_output(tmp_path: Path, export_module) -> None:
    source_root = tmp_path / "source"
    source_root.mkdir()
    (source_root / "README.md").write_text("changed\n", encoding="utf-8")
    output_root = tmp_path / "public"

    with pytest.raises(export_module.ExportError, match="source hash mismatch"):
        export_module.build_export(
            source_root,
            output_root,
            _manifest("README.md", "a" * 64),
            release=False,
            verify_git=False,
        )

    assert not output_root.exists()


def test_symlink_source_is_rejected(tmp_path: Path, export_module) -> None:
    outside = tmp_path / "outside.md"
    outside.write_text("outside\n", encoding="utf-8")
    source_root = tmp_path / "source"
    source_root.mkdir()
    linked_path = source_root / "README.md"
    linked_path.symlink_to(outside)
    output_root = tmp_path / "public"

    with pytest.raises(export_module.ExportError, match="source is a symlink"):
        export_module.build_export(
            source_root,
            output_root,
            _manifest("README.md", _sha256(outside)),
            release=False,
            verify_git=False,
        )

    assert not output_root.exists()


def test_symlink_source_root_is_rejected(tmp_path: Path, export_module) -> None:
    real_source = tmp_path / "real-source"
    real_source.mkdir()
    allowed_path = real_source / "README.md"
    allowed_path.write_text("source\n", encoding="utf-8")
    linked_source = tmp_path / "linked-source"
    linked_source.symlink_to(real_source, target_is_directory=True)

    with pytest.raises(export_module.ExportError, match="source root must not be a symlink"):
        export_module.build_export(
            linked_source,
            tmp_path / "public",
            _manifest("README.md", _sha256(allowed_path)),
            release=False,
            verify_git=False,
        )


def test_existing_output_is_never_overwritten(tmp_path: Path, export_module) -> None:
    source_root = tmp_path / "source"
    source_root.mkdir()
    allowed_path = source_root / "README.md"
    allowed_path.write_text("source\n", encoding="utf-8")
    output_root = tmp_path / "public"
    output_root.mkdir()
    sentinel = output_root / "keep.txt"
    sentinel.write_text("keep\n", encoding="utf-8")

    with pytest.raises(export_module.ExportError, match="output path already exists"):
        export_module.build_export(
            source_root,
            output_root,
            _manifest("README.md", _sha256(allowed_path)),
            release=False,
            verify_git=False,
        )

    assert sentinel.read_text(encoding="utf-8") == "keep\n"


def test_output_inside_source_tree_is_rejected(tmp_path: Path, export_module) -> None:
    source_root = tmp_path / "source"
    source_root.mkdir()
    allowed_path = source_root / "README.md"
    allowed_path.write_text("source\n", encoding="utf-8")

    with pytest.raises(export_module.ExportError, match="outside the source tree"):
        export_module.build_export(
            source_root,
            source_root / "public",
            _manifest("README.md", _sha256(allowed_path)),
            release=False,
            verify_git=False,
        )


def test_release_export_reads_pinned_commit_not_worktree(tmp_path: Path, export_module) -> None:
    repo_root = tmp_path / "repo"
    repo_root.mkdir()
    _git(repo_root, "init", "-q")
    readme = repo_root / "README.md"
    readme.write_text("baseline content\n", encoding="utf-8")
    baseline_commit = _git_commit_all(repo_root, "baseline")
    readme.write_text("frozen export content\n", encoding="utf-8")
    export_commit = _git_commit_all(repo_root, "frozen export")
    frozen_digest = _sha256_bytes(b"frozen export content\n")
    readme.write_text("dirty uncommitted content\n", encoding="utf-8")

    output_root = tmp_path / "public"
    result = export_module.build_export(
        repo_root,
        output_root,
        _manifest(
            "README.md",
            frozen_digest,
            baseline_commit=baseline_commit,
            export_commit=export_commit,
        ),
        release=True,
    )

    assert result == output_root
    assert (output_root / "README.md").read_text(encoding="utf-8") == "frozen export content\n"


def test_release_export_requires_existing_export_commit(tmp_path: Path, export_module) -> None:
    repo_root = tmp_path / "repo"
    repo_root.mkdir()
    _git(repo_root, "init", "-q")
    (repo_root / "README.md").write_text("baseline content\n", encoding="utf-8")
    baseline_commit = _git_commit_all(repo_root, "baseline")

    with pytest.raises(export_module.ExportError, match="export commit does not exist"):
        export_module.build_export(
            repo_root,
            tmp_path / "public",
            _manifest(
                "README.md",
                _sha256_bytes(b"baseline content\n"),
                baseline_commit=baseline_commit,
                export_commit="4" * 40,
            ),
            release=True,
        )


def test_release_export_requires_baseline_ancestry(tmp_path: Path, export_module) -> None:
    repo_root = tmp_path / "repo"
    repo_root.mkdir()
    _git(repo_root, "init", "-q")
    readme = repo_root / "README.md"
    readme.write_text("baseline content\n", encoding="utf-8")
    first_commit = _git_commit_all(repo_root, "first")
    readme.write_text("second content\n", encoding="utf-8")
    second_commit = _git_commit_all(repo_root, "second")

    with pytest.raises(export_module.ExportError, match="does not descend from the approved baseline"):
        export_module.build_export(
            repo_root,
            tmp_path / "public",
            _manifest(
                "README.md",
                _sha256_bytes(b"baseline content\n"),
                baseline_commit=second_commit,
                export_commit=first_commit,
            ),
            release=True,
        )


def test_release_export_rejects_excluded_product_ancestry(tmp_path: Path, export_module) -> None:
    repo_root = tmp_path / "repo"
    repo_root.mkdir()
    _git(repo_root, "init", "-q")
    readme = repo_root / "README.md"
    readme.write_text("baseline content\n", encoding="utf-8")
    baseline_commit = _git_commit_all(repo_root, "baseline")
    readme.write_text("frozen export content\n", encoding="utf-8")
    export_commit = _git_commit_all(repo_root, "frozen export")

    with pytest.raises(export_module.ExportError, match="excluded product restricted"):
        export_module.build_export(
            repo_root,
            tmp_path / "public",
            _manifest(
                "README.md",
                _sha256_bytes(b"frozen export content\n"),
                baseline_commit=baseline_commit,
                export_commit=export_commit,
                excluded_commit=baseline_commit,
            ),
            release=True,
        )


def test_release_export_rejects_symlink_blob_in_commit(tmp_path: Path, export_module) -> None:
    repo_root = tmp_path / "repo"
    repo_root.mkdir()
    _git(repo_root, "init", "-q")
    target = repo_root / "target.md"
    target.write_text("target content\n", encoding="utf-8")
    (repo_root / "README.md").symlink_to(target)
    baseline_commit = _git_commit_all(repo_root, "baseline with symlink")

    manifest = _manifest(
        "README.md",
        _sha256_bytes(b"target content\n"),
        baseline_commit=baseline_commit,
        export_commit=baseline_commit,
    )

    with pytest.raises(export_module.ExportError, match="symlink in commit"):
        export_module.build_export(repo_root, tmp_path / "public", manifest, release=True)


def test_release_export_rejects_blob_missing_from_commit(tmp_path: Path, export_module) -> None:
    repo_root = tmp_path / "repo"
    repo_root.mkdir()
    _git(repo_root, "init", "-q")
    (repo_root / "README.md").write_text("baseline content\n", encoding="utf-8")
    baseline_commit = _git_commit_all(repo_root, "baseline")
    (repo_root / "NEW.md").write_text("uncommitted file\n", encoding="utf-8")

    manifest = _manifest(
        "NEW.md",
        _sha256_bytes(b"uncommitted file\n"),
        baseline_commit=baseline_commit,
        export_commit=baseline_commit,
    )

    with pytest.raises(export_module.ExportError, match="missing from commit"):
        export_module.build_export(repo_root, tmp_path / "public", manifest, release=True)


def test_draft_from_commit_reads_pinned_tree(tmp_path: Path, export_module) -> None:
    repo_root = tmp_path / "repo"
    repo_root.mkdir()
    _git(repo_root, "init", "-q")
    readme = repo_root / "README.md"
    readme.write_text("frozen draft content\n", encoding="utf-8")
    pinned_commit = _git_commit_all(repo_root, "frozen draft")
    readme.write_text("dirty draft content\n", encoding="utf-8")

    manifest = _manifest("README.md", _sha256_bytes(b"frozen draft content\n"), status="draft")
    manifest["source"]["export_commit"] = "pending"
    manifest["files"][0]["reviewer"] = "pending"

    output_root = tmp_path / "public"
    result = export_module.build_export(
        repo_root,
        output_root,
        manifest,
        release=False,
        verify_git=False,
        from_commit=pinned_commit,
    )

    assert result == output_root
    assert (output_root / "README.md").read_text(encoding="utf-8") == "frozen draft content\n"


def test_release_rejects_from_commit_override(tmp_path: Path, export_module) -> None:
    repo_root = tmp_path / "repo"
    repo_root.mkdir()
    _git(repo_root, "init", "-q")
    (repo_root / "README.md").write_text("baseline content\n", encoding="utf-8")
    baseline_commit = _git_commit_all(repo_root, "baseline")

    manifest = _manifest(
        "README.md",
        _sha256_bytes(b"baseline content\n"),
        baseline_commit=baseline_commit,
        export_commit=baseline_commit,
    )

    with pytest.raises(export_module.ExportError, match="must use manifest source.export_commit"):
        export_module.build_export(
            repo_root,
            tmp_path / "public",
            manifest,
            release=True,
            from_commit="5" * 40,
        )
