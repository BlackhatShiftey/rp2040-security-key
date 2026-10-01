from __future__ import annotations

import json
import subprocess
import tempfile
import unittest
from pathlib import Path

from scripts import bootstrap_sources


PROJECT_ROOT = Path(__file__).resolve().parents[1]


def git(*args: str, cwd: Path) -> str:
    result = subprocess.run(
        ["git", *args],
        cwd=cwd,
        check=True,
        capture_output=True,
        text=True,
    )
    return result.stdout.strip()


class BuildHelperTest(unittest.TestCase):
    def test_lock_has_exact_pins_and_patch_digests(self) -> None:
        lock = bootstrap_sources.load_lock(PROJECT_ROOT / "sources.lock.json")
        self.assertEqual(len(lock["repositories"]), 7)
        self.assertEqual(len(lock["patches"]), 6)
        for patch in lock["patches"]:
            patch_path = PROJECT_ROOT / patch["patch"]
            self.assertEqual(bootstrap_sources.sha256_file(patch_path), patch["patch_sha256"])
            self.assertEqual(len(patch["before_sha256"]), 64)
            self.assertEqual(len(patch["after_sha256"]), 64)

    def test_status_validation_preserves_leading_git_status_column(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            repo_path = Path(directory) / "repo"
            repo_path.mkdir()
            git("init", cwd=repo_path)
            git("config", "user.name", "Offline Test", cwd=repo_path)
            git("config", "user.email", "offline@example.invalid", cwd=repo_path)
            tracked = repo_path / "tracked.c"
            tracked.write_text("before\n", encoding="utf-8")
            git("add", "tracked.c", cwd=repo_path)
            git("commit", "-m", "fixture", cwd=repo_path)
            git("remote", "add", "origin", "https://github.com/example/fixture.git", cwd=repo_path)
            head = git("rev-parse", "HEAD", cwd=repo_path)
            tracked.write_text("after\n", encoding="utf-8")
            spec = {
                "id": "fixture",
                "url": "https://github.com/example/fixture.git",
                "commit": head,
                "allowed_status_paths": ["tracked.c"],
            }
            bootstrap_sources.validate_repository(repo_path, spec)
            spec["allowed_status_paths"] = []
            with self.assertRaises(bootstrap_sources.BootstrapError):
                bootstrap_sources.validate_repository(repo_path, spec)

    def test_symlinked_destination_and_marker_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "sources"
            outside = Path(directory) / "outside"
            root.mkdir()
            outside.mkdir()
            (root / "escaped").symlink_to(outside, target_is_directory=True)
            with self.assertRaises(bootstrap_sources.BootstrapError):
                bootstrap_sources.reject_symlink_escape(root, root / "escaped/repo", "fixture")

            marker = outside / ".picokeys_dep_source"
            target = outside / "marker-target"
            target.write_text("unexpected\n", encoding="utf-8")
            marker.symlink_to(target)
            with self.assertRaises(bootstrap_sources.BootstrapError):
                bootstrap_sources.write_dependency_marker(outside, "expected\n", "fixture")

    def test_prepared_manifest_covers_tree_and_detects_tampering(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            sources = root / "sources"
            sources.mkdir()
            lock = {
                "repositories": [
                    {
                        "id": "mbedtls",
                        "path": "mbedtls",
                        "commit": "a" * 40,
                        "marker": "REPO=mbedtls\nREF=pinned\n",
                    },
                    {
                        "id": "tinycbor",
                        "path": "tinycbor",
                        "commit": "b" * 40,
                        "marker": "REPO=tinycbor\nREF=pinned\n",
                    },
                ],
                "patches": [],
            }
            for repo in lock["repositories"]:
                repo_path = sources / repo["path"]
                repo_path.mkdir()
                (repo_path / ".picokeys_dep_source").write_text(
                    repo["marker"], encoding="utf-8"
                )
            payload = sources / "mbedtls" / "payload.txt"
            payload.write_text("pinned source\n", encoding="utf-8")
            (sources / "mbedtls" / "safe-link").symlink_to("payload.txt")
            lock_path = root / "lock.json"
            lock_path.write_text(json.dumps(lock), encoding="utf-8")
            bootstrap_sources.write_manifest(sources, lock_path, lock)
            bootstrap_sources.verify_manifest(sources, lock_path, lock)

            payload.write_text("tampered\n", encoding="utf-8")
            with self.assertRaises(bootstrap_sources.BootstrapError):
                bootstrap_sources.verify_manifest(sources, lock_path, lock)

    def test_manifest_rejects_external_symlink(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            sources = root / "sources"
            sources.mkdir()
            outside = root / "outside.txt"
            outside.write_text("outside\n", encoding="utf-8")
            (sources / "escape").symlink_to(outside)
            with self.assertRaises(bootstrap_sources.BootstrapError):
                bootstrap_sources.collect_manifest_entries(sources)


if __name__ == "__main__":
    unittest.main()
