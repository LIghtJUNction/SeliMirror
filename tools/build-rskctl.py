#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Cross-compile the static AArch64 rskctl userspace helper; never execute it."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import struct
import subprocess
import tempfile


ROOT = Path(__file__).resolve().parents[1]
KP_COMMIT = "ef52c62b339bd2da51880922249bf4edef71b1cf"


def audit(data):
    if len(data) < 64:
        raise ValueError("compiler output is not an ELF executable")
    header = struct.unpack_from("<16sHHIQQQIHHHHHH", data)
    if header[0][:7] != b"\x7fELF\x02\x01\x01" or header[1:3] != (2, 183):
        raise ValueError("rskctl must be an ELF64 little-endian AArch64 ET_EXEC")
    offset, stride, count = header[5], header[9], header[10]
    if stride != 56 or not count or offset + stride * count > len(data):
        raise ValueError("invalid ELF program headers")
    for index in range(count):
        kind = struct.unpack_from("<I", data, offset + index * stride)[0]
        if kind in (2, 3):  # PT_DYNAMIC, PT_INTERP
            raise ValueError("rskctl must be statically linked without an interpreter")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    compiler = parser.add_mutually_exclusive_group()
    compiler.add_argument("--zig", type=Path, help="Zig 0.13.0 executable; uses aarch64-linux-musl")
    compiler.add_argument("--cc", help="cross compiler executable, e.g. an NDK aarch64 Clang wrapper")
    parser.add_argument("--out", type=Path, default=ROOT / "dist/rskctl")
    args = parser.parse_args()
    try:
        destination = args.out.expanduser().resolve()
        destination.parent.mkdir(parents=True, exist_ok=True)
        environment = os.environ.copy()
        if args.zig:
            executable = args.zig.expanduser().resolve()
            command = [str(executable), "cc", "-target", "aarch64-linux-musl"]
            cache = ROOT / "build/rskctl-cache"
            environment.setdefault("ZIG_GLOBAL_CACHE_DIR", str(cache / "global"))
            environment.setdefault("ZIG_LOCAL_CACHE_DIR", str(cache / "local"))
        else:
            executable = shutil.which(args.cc or "aarch64-linux-musl-gcc")
            if not executable:
                raise ValueError("cross compiler missing; pass --zig or --cc")
            command = [executable]
        version = subprocess.check_output(command + ["--version"], env=environment, text=True).splitlines()[0]
        source = ROOT / "tools/rskctl.c"
        with tempfile.TemporaryDirectory(prefix=".rskctl-build-", dir=destination.parent) as staging:
            binary = Path(staging) / "rskctl"
            flags = ["-static", "-std=c11", "-Os", "-Wall", "-Wextra", "-Werror",
                     "-fstack-protector-strong", "-fno-unwind-tables", "-fno-asynchronous-unwind-tables"]
            subprocess.run(command + flags + [str(source), "-o", str(binary)],
                           env=environment, check=True)
            data = binary.read_bytes()
            audit(data)
            binary.chmod(0o755)
            binary.replace(destination)
        manifest = {
            "helper": "rskctl", "module": "selimirror",
            "format": "static ELF64 little-endian AArch64 ET_EXEC",
            "compiler": version, "bytes": len(data),
            "kernelpatch_version": "0.13.9", "kernelpatch_commit": KP_COMMIT,
            "protocol_bit63": True,
            "source_sha256": hashlib.sha256(source.read_bytes()).hexdigest(),
            "artifact_sha256": hashlib.sha256(data).hexdigest(),
            "validation_scope": "cross-compiled and ELF-audited; this script never executes the helper",
        }
        report = destination.with_name(destination.name + "-build-manifest.json")
        report.write_text(json.dumps(manifest, indent=2) + "\n")
        print(f"PASS: {destination} ({len(data)} bytes, static AArch64)")
        print(f"SHA256: {manifest['artifact_sha256']}")
    except (OSError, ValueError, struct.error, subprocess.CalledProcessError) as error:
        parser.exit(1, f"rskctl build failed: {error}\n")


if __name__ == "__main__":
    main()
