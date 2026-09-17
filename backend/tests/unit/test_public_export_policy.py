"""Tests for the fail-closed public export policy checker."""

from __future__ import annotations

import hashlib
import importlib.util
import sys
from pathlib import Path

import pytest


SCRIPT_PATH = (Path(__file__).resolve().parents[3] / "scripts" / "check_public_tree.py").resolve()


@pytest.fixture(scope="module")
def policy_module():
    spec = importlib.util.spec_from_file_location("check_public_tree", SCRIPT_PATH)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules["check_public_tree"] = module
    spec.loader.exec_module(module)
    return module


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _manifest(path: str, digest: str, *, status: str = "approved") -> dict:
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
            "baseline_commit": "1" * 40,
            "export_commit": "4" * 40,
            "upstream_repository": "https://example.test/upstream",
            "upstream_merge_base": "2" * 40,
            "excluded_ancestor_commits": [
                {
                    "commit": "3" * 40,
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
                "source_commit": "1" * 40,
                "rights": "company-owned",
                "reviewer": "Test Reviewer",
                "sha256": digest,
            }
        ],
    }


def test_approved_exact_allowlist_passes(tmp_path: Path, policy_module) -> None:
    export_root = tmp_path / "export"
    export_root.mkdir()
    license_path = export_root / "LICENSE.md"
    license_path.write_text("MIT test fixture\n", encoding="utf-8")

    result = policy_module.check_export_tree(
        export_root,
        _manifest("LICENSE.md", _sha256(license_path)),
        release=True,
    )

    assert result.ok, result.errors


def test_unlisted_file_fails(tmp_path: Path, policy_module) -> None:
    export_root = tmp_path / "export"
    export_root.mkdir()
    license_path = export_root / "LICENSE.md"
    license_path.write_text("MIT test fixture\n", encoding="utf-8")
    (export_root / "notes.txt").write_text("not reviewed\n", encoding="utf-8")

    result = policy_module.check_export_tree(
        export_root,
        _manifest("LICENSE.md", _sha256(license_path)),
        release=True,
    )

    assert any("file is not allowlisted: notes.txt" in error for error in result.errors)


def test_secret_path_fails_even_when_allowlisted(tmp_path: Path, policy_module) -> None:
    export_root = tmp_path / "export"
    export_root.mkdir()
    secret_path = export_root / ".env"
    secret_path.write_text("TOKEN=test-fixture\n", encoding="utf-8")

    result = policy_module.check_export_tree(
        export_root,
        _manifest(".env", _sha256(secret_path)),
        release=True,
    )

    assert any("forbidden path .env" in error for error in result.errors)


def test_excluded_product_path_fails_even_when_allowlisted(tmp_path: Path, policy_module) -> None:
    export_root = tmp_path / "export"
    restricted_path = export_root / "backend" / "src" / "learning" / "restricted_service.py"
    restricted_path.parent.mkdir(parents=True)
    restricted_path.write_text("EXCLUDED_PRODUCT = True\n", encoding="utf-8")

    result = policy_module.check_export_tree(
        export_root,
        _manifest("backend/src/learning/restricted_service.py", _sha256(restricted_path)),
        release=True,
    )

    assert any("matches a manifest deny rule" in error for error in result.errors)


def test_symlink_fails_even_when_allowlisted(tmp_path: Path, policy_module) -> None:
    outside = tmp_path / "outside.txt"
    outside.write_text("outside export root\n", encoding="utf-8")
    export_root = tmp_path / "export"
    export_root.mkdir()
    link_path = export_root / "linked.txt"
    link_path.symlink_to(outside)

    result = policy_module.check_export_tree(
        export_root,
        _manifest("linked.txt", _sha256(outside)),
        release=True,
    )

    assert any("symlink is forbidden: linked.txt" in error for error in result.errors)


def test_git_lfs_pointer_fails(tmp_path: Path, policy_module) -> None:
    export_root = tmp_path / "export"
    export_root.mkdir()
    pointer_path = export_root / "asset.bin"
    pointer_path.write_text(
        "version https://git-lfs.github.com/spec/v1\n"
        "oid sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n"
        "size 42\n",
        encoding="utf-8",
    )

    result = policy_module.check_export_tree(
        export_root,
        _manifest("asset.bin", _sha256(pointer_path)),
        release=True,
    )

    assert any("Git LFS pointer is forbidden: asset.bin" in error for error in result.errors)


def test_release_mode_rejects_pending_review(policy_module) -> None:
    manifest = _manifest("LICENSE.md", "pending", status="draft")
    manifest["files"][0]["rights"] = "pending"
    manifest["files"][0]["reviewer"] = "pending"

    result = policy_module.validate_manifest(manifest, release=True)

    assert not result.ok
    assert "release check requires manifest status approved" in result.errors
    assert any("rights is not approved" in error for error in result.errors)
    assert any("reviewer is not assigned" in error for error in result.errors)
    assert any("sha256 must be an approved file hash" in error for error in result.errors)


def test_manifest_requires_matching_source_product_scope(policy_module) -> None:
    manifest = _manifest("LICENSE.md", "a" * 64)
    manifest["source"]["product_scope"] = "other"

    result = policy_module.validate_manifest(manifest, release=True)

    assert "source.product_scope must match project.product_scope" in result.errors


def test_release_mode_requires_export_commit(policy_module) -> None:
    manifest = _manifest("LICENSE.md", "a" * 64)
    manifest["source"]["export_commit"] = "pending"

    release_result = policy_module.validate_manifest(manifest, release=True)
    draft_result = policy_module.validate_manifest(manifest, release=False)

    assert "source.export_commit must be a full lowercase Git commit ID" in release_result.errors
    assert "source.export_commit is pending" in draft_result.warnings


def test_manifest_requires_baseline_commit(policy_module) -> None:
    manifest = _manifest("LICENSE.md", "a" * 64)
    del manifest["source"]["baseline_commit"]

    result = policy_module.validate_manifest(manifest, release=False)

    assert "source.baseline_commit must be a full lowercase Git commit ID" in result.errors
