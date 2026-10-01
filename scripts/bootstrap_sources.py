#!/usr/bin/env python3
"""Clone, pin, validate, and patch the public RP2040 security-key sources."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import stat
import subprocess
import sys
from pathlib import Path
from typing import Any


PROJECT_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_LOCK = PROJECT_ROOT / "sources.lock.json"
DEFAULT_SOURCE_DIR = PROJECT_ROOT / "build" / "public-sources"
MANIFEST_NAME = "source-manifest.json"


class BootstrapError(RuntimeError):
    pass


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def run(command: list[str], *, cwd: Path | None = None) -> str:
    completed = subprocess.run(
        command,
        cwd=cwd,
        check=False,
        capture_output=True,
        text=True,
    )
    if completed.returncode != 0:
        label = " ".join(command[:3])
        raise BootstrapError(f"command failed ({completed.returncode}): {label}")
    return completed.stdout.rstrip("\n")


def safe_relative(value: object, label: str) -> Path:
    if not isinstance(value, str) or not value:
        raise BootstrapError(f"invalid {label}")
    path = Path(value)
    if path.is_absolute() or ".." in path.parts:
        raise BootstrapError(f"unsafe {label}: {value}")
    return path


def normalized_github_url(value: str) -> str:
    text = value.strip()
    if text.startswith("git@github.com:"):
        text = "github.com/" + text.removeprefix("git@github.com:")
    elif "://" in text:
        text = text.split("://", 1)[1]
    return text.rstrip("/").removesuffix(".git").lower()


def load_lock(path: Path) -> dict[str, Any]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise BootstrapError("unable to read a valid source lock") from exc
    if not isinstance(payload, dict) or payload.get("schema") != 1:
        raise BootstrapError("unsupported source lock schema")
    repositories = payload.get("repositories")
    patches = payload.get("patches")
    if not isinstance(repositories, list) or len(repositories) != 7:
        raise BootstrapError("source lock must contain exactly seven repositories")
    if not isinstance(patches, list) or len(patches) != 5:
        raise BootstrapError("source lock must contain exactly five patches")
    ids = [item.get("id") for item in repositories if isinstance(item, dict)]
    if len(ids) != len(set(ids)) or len(ids) != 7:
        raise BootstrapError("source lock repository identifiers are invalid")
    return payload


def git_root(path: Path) -> Path | None:
    completed = subprocess.run(
        ["git", "-C", str(path), "rev-parse", "--show-toplevel"],
        check=False,
        capture_output=True,
        text=True,
    )
    if completed.returncode != 0:
        return None
    return Path(completed.stdout.strip()).resolve()


def reject_symlink_escape(source_dir: Path, destination: Path, label: str) -> None:
    root = source_dir.resolve()
    resolved = destination.resolve(strict=False)
    if not resolved.is_relative_to(root):
        raise BootstrapError(f"{label}: destination escapes the selected source directory")
    current = root
    for part in destination.relative_to(source_dir).parts:
        current /= part
        if current.is_symlink():
            raise BootstrapError(f"{label}: refusing symlinked source path")


def validate_repository(path: Path, repo: dict[str, Any]) -> None:
    if git_root(path) != path.resolve():
        raise BootstrapError(f"{repo['id']}: existing path is not the expected Git root")
    head = run(["git", "-C", str(path), "rev-parse", "HEAD"])
    if head != repo.get("commit"):
        raise BootstrapError(f"{repo['id']}: existing checkout is at an unexpected commit")
    origin = run(["git", "-C", str(path), "remote", "get-url", "origin"])
    if normalized_github_url(origin) != normalized_github_url(str(repo.get("url", ""))):
        raise BootstrapError(f"{repo['id']}: existing checkout has an unexpected origin")

    allowed = set(repo.get("allowed_status_paths", []))
    status = run(
        [
            "git",
            "-C",
            str(path),
            "status",
            "--porcelain=v1",
            "--untracked-files=all",
        ]
    )
    for line in status.splitlines():
        changed_path = line[3:].split(" -> ")[-1]
        if changed_path not in allowed:
            raise BootstrapError(f"{repo['id']}: unexpected local change at {changed_path}")


def clone_or_validate(source_dir: Path, repo: dict[str, Any]) -> Path:
    relative = safe_relative(repo.get("path"), f"repository path for {repo.get('id')}")
    destination = source_dir / relative
    reject_symlink_escape(source_dir, destination, str(repo.get("id")))
    created = False
    if destination.exists():
        if git_root(destination) != destination.resolve():
            if not destination.is_dir() or any(destination.iterdir()):
                raise BootstrapError(f"{repo['id']}: refusing unexpected existing path")
            created = True
    else:
        created = True

    if created:
        destination.parent.mkdir(parents=True, exist_ok=True)
        run(
            [
                "gh",
                "repo",
                "clone",
                str(repo["slug"]),
                str(destination),
                "--",
                "--no-checkout",
            ]
        )
        run(
            [
                "git",
                "-C",
                str(destination),
                "checkout",
                "--detach",
                str(repo["commit"]),
            ]
        )
    validate_repository(destination, repo)
    return destination


def write_dependency_marker(repo_path: Path, expected: str, repo_id: str) -> None:
    marker = repo_path / ".picokeys_dep_source"
    if marker.is_symlink():
        raise BootstrapError(f"{repo_id}: refusing symlinked dependency source marker")
    if marker.exists():
        if not marker.is_file() or marker.read_text(encoding="utf-8") != expected:
            raise BootstrapError(f"{repo_id}: dependency source marker is unexpected")
        return
    marker.write_text(expected, encoding="utf-8")


def apply_patch(
    project_root: Path,
    repositories: dict[str, Path],
    patch: dict[str, Any],
) -> str:
    repo_id = str(patch.get("repo", ""))
    if repo_id not in repositories:
        raise BootstrapError(f"patch references unknown repository: {repo_id}")
    patch_path = project_root / safe_relative(patch.get("patch"), "patch path")
    target = repositories[repo_id] / safe_relative(patch.get("target"), "patch target")
    if not patch_path.is_file() or not target.is_file():
        raise BootstrapError(f"patch input is missing: {patch.get('patch')}")
    if sha256_file(patch_path) != patch.get("patch_sha256"):
        raise BootstrapError(f"patch digest mismatch: {patch.get('patch')}")

    current = sha256_file(target)
    if current == patch.get("after_sha256"):
        return "already-applied"
    if current != patch.get("before_sha256"):
        raise BootstrapError(f"unexpected pre-patch digest: {patch.get('target')}")

    repository = repositories[repo_id]
    run(["git", "-C", str(repository), "apply", "--check", str(patch_path)])
    run(["git", "-C", str(repository), "apply", str(patch_path)])
    if sha256_file(target) != patch.get("after_sha256"):
        raise BootstrapError(f"post-patch digest mismatch: {patch.get('target')}")
    return "applied"


def validate_third_party_layout(sdk_path: Path) -> None:
    third_party = sdk_path / "third-party"
    expected = {"mbedtls", "tinycbor"}
    actual = {entry.name for entry in third_party.iterdir()} if third_party.is_dir() else set()
    if actual != expected:
        raise BootstrapError("pico-keys-sdk: third-party layout contains unexpected paths")


def collect_manifest_entries(source_dir: Path) -> list[dict[str, Any]]:
    entries: list[dict[str, Any]] = []
    for current_root, directory_names, file_names in os.walk(source_dir, followlinks=False):
        current = Path(current_root)
        if ".git" in directory_names:
            directory_names.remove(".git")
        for name in list(directory_names):
            path = current / name
            if path.is_symlink():
                directory_names.remove(name)
                target = os.readlink(path)
                resolved = (path.parent / target).resolve(strict=False)
                if (
                    Path(target).is_absolute()
                    or not resolved.is_relative_to(source_dir.resolve())
                    or not resolved.exists()
                ):
                    raise BootstrapError(f"manifest refuses external symlink: {path}")
                entries.append(
                    {
                        "path": path.relative_to(source_dir).as_posix(),
                        "type": "symlink",
                        "target": target,
                    }
                )
        for name in file_names:
            path = current / name
            relative = path.relative_to(source_dir).as_posix()
            if name == ".git" or relative == MANIFEST_NAME:
                continue
            if path.is_symlink():
                target = os.readlink(path)
                resolved = (path.parent / target).resolve(strict=False)
                if (
                    Path(target).is_absolute()
                    or not resolved.is_relative_to(source_dir.resolve())
                    or not resolved.exists()
                ):
                    raise BootstrapError(f"manifest refuses external symlink: {path}")
                entries.append({"path": relative, "type": "symlink", "target": target})
            elif path.is_file():
                metadata = path.stat()
                entries.append(
                    {
                        "path": relative,
                        "type": "file",
                        "size": metadata.st_size,
                        "mode": stat.S_IMODE(metadata.st_mode),
                        "sha256": sha256_file(path),
                    }
                )
            else:
                raise BootstrapError(f"manifest refuses special file: {path}")
    return sorted(entries, key=lambda item: item["path"])


def manifest_payload(source_dir: Path, lock_path: Path, lock: dict[str, Any]) -> dict[str, Any]:
    return {
        "schema": 1,
        "trust_boundary": "integrity-only; authenticate the release archive SHA-256 externally",
        "lock_sha256": sha256_file(lock_path),
        "repositories": [
            {"id": item["id"], "path": item["path"], "commit": item["commit"]}
            for item in lock["repositories"]
        ],
        "entries": collect_manifest_entries(source_dir),
    }


def validate_source_root_layout(source_dir: Path, lock: dict[str, Any], include_manifest: bool) -> None:
    expected = {Path(item["path"]).parts[0] for item in lock["repositories"]}
    if include_manifest:
        expected.add(MANIFEST_NAME)
    actual = {entry.name for entry in source_dir.iterdir()}
    if actual != expected:
        raise BootstrapError("source root contains missing or unexpected top-level paths")


def write_manifest(source_dir: Path, lock_path: Path, lock: dict[str, Any]) -> Path:
    manifest = source_dir / MANIFEST_NAME
    if manifest.is_symlink():
        raise BootstrapError("refusing symlinked source manifest")
    payload = manifest_payload(source_dir, lock_path, lock)
    temporary = source_dir / f".{MANIFEST_NAME}.{os.getpid()}.tmp"
    if temporary.exists() or temporary.is_symlink():
        raise BootstrapError("refusing unexpected temporary source manifest")
    try:
        temporary.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        temporary.replace(manifest)
    finally:
        if temporary.exists():
            temporary.unlink()
    return manifest


def verify_manifest(source_dir: Path, lock_path: Path, lock: dict[str, Any]) -> None:
    validate_source_root_layout(source_dir, lock, include_manifest=True)
    manifest = source_dir / MANIFEST_NAME
    if manifest.is_symlink() or not manifest.is_file():
        raise BootstrapError("prepared sources require a regular source manifest")
    try:
        saved = json.loads(manifest.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise BootstrapError("prepared source manifest is invalid") from exc
    expected_metadata = manifest_payload(source_dir, lock_path, lock)
    if saved != expected_metadata:
        raise BootstrapError("prepared source manifest does not match the expanded source tree")
    for patch in lock["patches"]:
        repo = next(item for item in lock["repositories"] if item["id"] == patch["repo"])
        target = source_dir / repo["path"] / patch["target"]
        if not target.is_file() or sha256_file(target) != patch["after_sha256"]:
            raise BootstrapError(f"prepared source patch digest mismatch: {patch['target']}")
    for repo_id in ("mbedtls", "tinycbor"):
        repo = next(item for item in lock["repositories"] if item["id"] == repo_id)
        marker = source_dir / repo["path"] / ".picokeys_dep_source"
        if (
            marker.is_symlink()
            or not marker.is_file()
            or marker.read_text(encoding="utf-8") != repo["marker"]
        ):
            raise BootstrapError(f"prepared dependency marker mismatch: {repo_id}")


def bootstrap(source_dir: Path, lock_path: Path) -> None:
    if shutil.which("git") is None or shutil.which("gh") is None:
        raise BootstrapError("git and the GitHub CLI (gh) are required")
    lock = load_lock(lock_path)
    source_dir.mkdir(parents=True, exist_ok=True)

    repository_specs = {item["id"]: item for item in lock["repositories"]}
    repository_paths: dict[str, Path] = {}
    for repo in lock["repositories"]:
        path = clone_or_validate(source_dir, repo)
        repository_paths[repo["id"]] = path
        print(f"source={repo['id']} commit={repo['commit']}")

    validate_third_party_layout(repository_paths["pico-keys-sdk"])
    for repo_id in ("mbedtls", "tinycbor"):
        spec = repository_specs[repo_id]
        write_dependency_marker(repository_paths[repo_id], spec["marker"], repo_id)

    for patch in sorted(lock["patches"], key=lambda item: item["order"]):
        state = apply_patch(PROJECT_ROOT, repository_paths, patch)
        print(f"patch={patch['order']} state={state} target={patch['target']}")

    for repo in lock["repositories"]:
        validate_repository(repository_paths[repo["id"]], repo)
    for patch in lock["patches"]:
        target = repository_paths[patch["repo"]] / patch["target"]
        if sha256_file(target) != patch["after_sha256"]:
            raise BootstrapError(f"final source digest mismatch: {patch['target']}")
    validate_source_root_layout(
        source_dir,
        lock,
        include_manifest=(source_dir / MANIFEST_NAME).exists(),
    )
    manifest = write_manifest(source_dir, lock_path, lock)
    print(f"bootstrap=PASS source_dir={source_dir}")
    print(f"source_manifest={manifest}")


def verify_prepared_sources(source_dir: Path, lock_path: Path) -> None:
    lock = load_lock(lock_path)
    verify_manifest(source_dir, lock_path, lock)
    print(f"prepared_sources=PASS source_dir={source_dir}")
    print("prepared_sources_trust=integrity-only_authenticate-release-archive-sha256-externally")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-dir", type=Path, default=DEFAULT_SOURCE_DIR)
    parser.add_argument("--lock", type=Path, default=DEFAULT_LOCK)
    parser.add_argument(
        "--verify-manifest-only",
        action="store_true",
        help="validate an expanded publisher archive without requiring Git metadata",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        if args.verify_manifest_only:
            verify_prepared_sources(args.source_dir.resolve(), args.lock.resolve())
        else:
            bootstrap(args.source_dir.resolve(), args.lock.resolve())
    except BootstrapError as exc:
        print(f"bootstrap=FAIL reason={exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
