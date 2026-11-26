# Copyright 2026 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Helper CLI for OSS Exit Gate PyPI staging cleanup and manifest creation."""

from __future__ import annotations

import argparse
import email
import json
import pathlib
import re
import subprocess
import sys
import tarfile
import zipfile

_PEP503_NORMALIZE_RE = re.compile(r"[-_.]+")
_NOT_FOUND_RE = re.compile(r"NOT_FOUND|not found|404", re.IGNORECASE)


def normalize_package_name(name: str) -> str:
    """Normalize a Python package name per PEP 503."""
    return _PEP503_NORMALIZE_RE.sub("-", name.strip()).lower()


def _parse_metadata(raw: bytes, source: pathlib.Path) -> tuple[str, str]:
    msg = email.message_from_bytes(raw)
    name = msg.get("Name")
    version = msg.get("Version")
    if not name or not version:
        raise SystemExit(
            f"ERROR: Missing Name/Version metadata header in {source}"
        )
    return normalize_package_name(name), version.strip()


def collect_packages(dist_dir: pathlib.Path) -> list[tuple[str, str]]:
    """Extract sorted unique (name, version) pairs from built distributions."""
    packages: set[tuple[str, str]] = set()
    for wheel_path in sorted(dist_dir.glob("*.whl")):
        with zipfile.ZipFile(wheel_path) as zf:
            for member_name in zf.namelist():
                if (
                    member_name.endswith(".dist-info/METADATA")
                    and member_name.count("/") == 1
                ):
                    packages.add(_parse_metadata(zf.read(member_name), wheel_path))
                    break

    for sdist_path in sorted(dist_dir.glob("*.tar.gz")):
        with tarfile.open(sdist_path, "r:gz") as tf:
            for member in tf.getmembers():
                if (
                    member.name.endswith("/PKG-INFO")
                    and member.name.count("/") == 1
                ):
                    extracted = tf.extractfile(member)
                    if extracted is not None:
                        packages.add(_parse_metadata(extracted.read(), sdist_path))
                    break

    if not packages:
        raise SystemExit(
            f"ERROR: No .whl or .tar.gz metadata found under {dist_dir}"
        )
    return sorted(packages)


def cmd_cleanup(args: argparse.Namespace) -> int:
    """Delete only exact prior staged versions matching artifacts in dist_dir."""
    packages = collect_packages(args.dist_dir)
    for pkg, version in packages:
        describe_cmd = [
            "gcloud",
            "artifacts",
            "versions",
            "describe",
            version,
            f"--package={pkg}",
            f"--project={args.project}",
            f"--location={args.location}",
            f"--repository={args.repository}",
            "--format=value(name)",
        ]
        result = subprocess.run(
            describe_cmd,
            capture_output=True,
            text=True,
            check=False,
        )
        if result.returncode == 0:
            print(f"Deleting prior staged attempt: {pkg}@{version}")
            delete_cmd = [
                "gcloud",
                "artifacts",
                "versions",
                "delete",
                version,
                f"--package={pkg}",
                f"--project={args.project}",
                f"--location={args.location}",
                f"--repository={args.repository}",
                "--quiet",
            ]
            subprocess.run(delete_cmd, check=True)
        elif not _NOT_FOUND_RE.search(result.stderr):
            sys.stderr.write(result.stderr)
            return result.returncode or 1
    return 0


def cmd_manifest(args: argparse.Namespace) -> int:
    """Write an explicit, version-scoped OSS Exit Gate manifest JSON file."""
    packages = collect_packages(args.dist_dir)
    manifest = {
        "publish_all": False,
        "publishing_groups": [
            {
                "packages": [
                    {"name": pkg, "version": version} for pkg, version in packages
                ]
            }
        ],
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("w", encoding="utf-8") as fh:
        json.dump(manifest, fh, indent=2)
        fh.write("\n")
    return 0


def build_parser() -> argparse.ArgumentParser:
    """Build the CLI argument parser."""
    parser = argparse.ArgumentParser(
        description="OSS Exit Gate PyPI staging helper."
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    cleanup_parser = subparsers.add_parser(
        "cleanup",
        help="Delete prior staged Artifact Registry versions matching dist/.",
    )
    cleanup_parser.add_argument(
        "--dist-dir",
        type=pathlib.Path,
        default=pathlib.Path("dist"),
        help="Directory containing built .whl / .tar.gz distributions.",
    )
    cleanup_parser.add_argument("--project", required=True)
    cleanup_parser.add_argument("--location", required=True)
    cleanup_parser.add_argument("--repository", required=True)
    cleanup_parser.set_defaults(func=cmd_cleanup)

    manifest_parser = subparsers.add_parser(
        "manifest",
        help="Generate an explicit publish_all=false manifest JSON file.",
    )
    manifest_parser.add_argument(
        "--dist-dir",
        type=pathlib.Path,
        default=pathlib.Path("dist"),
        help="Directory containing built .whl / .tar.gz distributions.",
    )
    manifest_parser.add_argument(
        "--output",
        type=pathlib.Path,
        required=True,
        help="Output path for the generated manifest JSON.",
    )
    manifest_parser.set_defaults(func=cmd_manifest)

    return parser


def main(argv: list[str] | None = None) -> int:
    """Entry point."""
    parser = build_parser()
    args = parser.parse_args(argv)
    return int(args.func(args))


if __name__ == "__main__":
    raise SystemExit(main())
