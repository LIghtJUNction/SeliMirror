#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Fetch the exact public source revisions used by this module."""

from __future__ import annotations

import argparse
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile


KERNEL = (
    "android_kernel_xiaomi_sm8150",
    "https://github.com/Laulan56/android_kernel_xiaomi_sm8150.git",
    "bd65f57d4c36882a5dfd34557e64198516ed392b",
)
EXFAT_REVISION = "034f47d607c441e7fb5be3eb71d7a289ef76bc0c"
REFERENCES = (
    (
        "KernelPatch",
        "https://github.com/bmax121/KernelPatch.git",
        "ef52c62b339bd2da51880922249bf4edef71b1cf",
    ),
    (
        "BakaSU",
        "https://github.com/Baka-SU/BakaSU.git",
        "896e8981e0ed76ec14d1dcb39ab793438b304886",
    ),
    (
        "Kam",
        "https://github.com/MemDeco-WG/Kam.git",
        "3835842ca90cefc621383e72e01078481122aa30",
    ),
)


def git(path: Path, *args: str, capture: bool = False) -> str:
    result = subprocess.run(
        ["git", "-C", str(path), *args],
        check=True,
        text=True,
        stdout=subprocess.PIPE if capture else None,
    )
    return result.stdout.strip() if capture else ""


def verify(path: Path, revision: str) -> None:
    if not (path / ".git").exists():
        raise ValueError(f"Existing path is not a Git checkout: {path}")
    actual = git(path, "rev-parse", "HEAD", capture=True)
    if actual != revision:
        raise ValueError(
            f"Refusing to change {path}: HEAD is {actual}, expected {revision}. "
            "Use a separate --destination."
        )
    if git(path, "status", "--porcelain", "--untracked-files=normal", capture=True):
        raise ValueError(f"Refusing to change a checkout with local changes: {path}")


def fetch(destination: Path, source: tuple[str, str, str]) -> Path:
    name, url, revision = source
    path = destination / name
    if path.exists() or path.is_symlink():
        verify(path, revision)
        print(f"Verified {path} @ {revision}", flush=True)
        return path

    # A failed download never replaces an existing checkout. Only this
    # invocation's temporary directory is removed during failure cleanup.
    staging = Path(tempfile.mkdtemp(prefix=f".{name}-fetch-", dir=destination))
    try:
        print(f"Fetching {url} @ {revision}", flush=True)
        git(staging, "init", "--quiet")
        git(staging, "remote", "add", "origin", url)
        git(staging, "fetch", "--quiet", "--depth=1", "--filter=blob:none", "origin", revision)
        git(staging, "checkout", "--quiet", "--detach", revision)
        verify(staging, revision)
        staging.rename(path)
    finally:
        if staging.exists():
            shutil.rmtree(staging)
    return path


def fetch_exfat(kernel: Path) -> None:
    entry = git(kernel, "ls-tree", "HEAD", "fs/exfat", capture=True).split()
    if entry[:3] != ["160000", "commit", EXFAT_REVISION]:
        raise ValueError("The kernel's exFAT submodule pin does not match this module.")
    exfat = kernel / "fs/exfat"
    if (exfat / ".git").exists():
        verify(exfat, EXFAT_REVISION)
    else:
        if exfat.exists() and any(exfat.iterdir()):
            raise ValueError(f"Refusing to replace existing files in {exfat}")
        git(kernel, "submodule", "update", "--init", "--depth=1", "fs/exfat")
        verify(exfat, EXFAT_REVISION)
    print(f"Verified {exfat} @ {EXFAT_REVISION}", flush=True)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--destination",
        type=Path,
        default=Path(__file__).resolve().parents[1] / "third_party",
        help="Checkout parent directory (default: project/third_party).",
    )
    parser.add_argument(
        "--references",
        action="store_true",
        help="Also fetch KernelPatch, BakaSU (the ReSukiSU redirect), and Kam.",
    )
    args = parser.parse_args()
    if shutil.which("git") is None:
        parser.error("git is required")
    destination = args.destination.expanduser().resolve()
    try:
        destination.mkdir(parents=True, exist_ok=True)
        kernel = fetch(destination, KERNEL)
        fetch_exfat(kernel)
        if args.references:
            for source in REFERENCES:
                fetch(destination, source)
    except (OSError, ValueError, subprocess.CalledProcessError) as error:
        print(f"Source fetch failed: {error}", file=sys.stderr)
        return 1
    print("Source revisions verified. No commits or pushes were made.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
