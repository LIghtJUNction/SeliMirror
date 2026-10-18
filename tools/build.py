#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Build against prepared, pinned Xiaomi MIUI kernel headers; no kernel image build."""
import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
from pathlib import Path

from check_kpm import audit

ROOT = Path(__file__).resolve().parents[1]
KERNEL_COMMIT = "bd65f57d4c36882a5dfd34557e64198516ed392b"
SOURCES = ("core.c", "policy.c", "kernel_api.c", "memory.c", "gateway.c", "main.c", "gateway.S")


def output(argv):
    return subprocess.check_output([str(arg) for arg in argv], text=True).strip()


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def config_map(path):
    result = {}
    for line in Path(path).read_text().splitlines():
        match = re.fullmatch(r"(CONFIG_\w+)=(.*)", line)
        if match:
            result[match[1]] = match[2]
    return result


def validate_headers(kernel, out):
    commit = output(["git", "-C", kernel, "rev-parse", "HEAD"])
    if commit != KERNEL_COMMIT:
        raise ValueError(f"requires kernel commit {KERNEL_COMMIT}; got {commit}")
    subprocess.run(["git", "-C", str(kernel), "diff", "--quiet", "HEAD", "--"], check=True)
    required = (
        ".config", "include/generated/autoconf.h", "include/generated/utsrelease.h",
        "include/generated/uapi/linux/version.h", "include/generated/bounds.h",
        "security/selinux/flask.h", "security/selinux/av_permissions.h",
    )
    for name in required:
        if not (out / name).is_file():
            raise ValueError(f"missing prepared header/config {out / name}; run tools/prepare-kernel.sh")
    config = config_map(out / ".config")
    for name in ("ARM64", "ARM64_4K_PAGES", "SECURITY_SELINUX", "KALLSYMS", "KALLSYMS_ALL", "MODULES"):
        if config.get("CONFIG_" + name) != "y":
            raise ValueError(f"CONFIG_{name}=y is required")
    for name in ("DEBUG_SPINLOCK", "DEBUG_LOCK_ALLOC", "GENERIC_LOCKBREAK", "GCC_PLUGIN_RANDSTRUCT",
                 "RANDSTRUCT", "CFI_CLANG", "CFI", "LTO_CLANG", "LTO", "SHADOW_CALL_STACK", "KASAN"):
        if config.get("CONFIG_" + name) in {"y", "m"}:
            raise ValueError(f"CONFIG_{name} is not supported by this audited module build")
    definitions = dict(re.findall(r"^#define (CONFIG_\w+) (.+)$",
                                  (out / "include/generated/autoconf.h").read_text(), re.M))
    expected = {}
    for key, value in config.items():
        if value == "y":
            expected[key] = "1"
        elif value == "m":
            expected[key + "_MODULE"] = "1"
        elif value != "n":
            expected[key] = value
    if expected != definitions:
        changed = sorted(key for key in expected.keys() | definitions.keys()
                         if expected.get(key) != definitions.get(key))
        raise ValueError(f".config and autoconf.h disagree: {', '.join(changed[:12])}; rerun prepare0")
    match = re.fullmatch(r'#define UTS_RELEASE "([^"]+)"\s*',
                        (out / "include/generated/utsrelease.h").read_text())
    if not match or not match[1].startswith("4.14.268"):
        raise ValueError("unexpected prepared kernel release")
    return match[1]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--kernel", type=Path, required=True)
    parser.add_argument("--kernel-out", type=Path, required=True)
    parser.add_argument("--build-dir", type=Path, default=ROOT / "build")
    parser.add_argument("--dist", type=Path, default=ROOT / "dist")
    parser.add_argument("--zig", type=Path, help="Zig 0.13.0 binary; uses its Clang/LLD 18.1.6")
    parser.add_argument("--cc", default="clang", help="native Clang or aarch64-linux-gnu-gcc executable")
    parser.add_argument("--ld", default="ld.lld", help="LLD or aarch64-linux-gnu-ld executable")
    args = parser.parse_args()
    try:
        kernel, out = args.kernel.resolve(), args.kernel_out.resolve()
        release = validate_headers(kernel, out)
        build, dist = args.build_dir.resolve(), args.dist.resolve()
        build.mkdir(parents=True, exist_ok=True)
        dist.mkdir(parents=True, exist_ok=True)
        if args.zig:
            zig = args.zig.resolve()
            env = json.loads(output([zig, "env"]))
            resource = Path(env["lib_dir"]).resolve()
            compiler = [str(zig), "clang", "--target=aarch64-linux-gnu", "-resource-dir=" + str(resource)]
            linker = [str(zig), "ld.lld"]
            builtin_include = resource / "include"
            clang = True
        else:
            if not shutil.which(args.cc) or not shutil.which(args.ld):
                raise ValueError("cross compiler/linker missing; use --zig or --cc/--ld")
            compiler, linker = [args.cc], [args.ld]
            clang = "clang" in output(compiler + ["--version"]).lower()
            if clang:
                compiler += ["--target=aarch64-linux-gnu"]
            builtin_include = Path(output(compiler + ["-print-file-name=include"]))
        version = output(compiler + ["--version"]).splitlines()[0]
        linker_version = output(linker + ["--version"]).splitlines()[0]
        config_sha = digest(out / ".config")
        profile = {
            "RSK_KERNEL_RELEASE": release,
            "RSK_CONFIG_SHA256": config_sha,
            "RSK_KERNEL_COMMIT": KERNEL_COMMIT,
        }
        header = "/* Generated by tools/build.py; do not edit. */\n"
        header += "".join(f"#define {key} {json.dumps(value)}\n" for key, value in profile.items())
        (build / "build_profile.h").write_text(header)
        includes = [kernel / "arch/arm64/include", out / "arch/arm64/include/generated",
                    kernel / "include", out / "include", kernel / "arch/arm64/include/uapi",
                    out / "arch/arm64/include/generated/uapi", kernel / "include/uapi",
                    out / "include/generated/uapi", kernel / "security/selinux",
                    kernel / "security/selinux/include", out / "security/selinux",
                    ROOT / "include", build]
        common = ["-D__KERNEL__", "-DMODULE", '-DKBUILD_MODNAME="resukisu_selinux_kpm"',
                  "-D__NO_FORTIFY", "-nostdinc", "-isystem", str(builtin_include),
                  "-include", str(kernel / "include/linux/kconfig.h")]
        common += [flag for path in includes for flag in ("-I", str(path))]
        cflags = ["-std=gnu11", "-O2", "-g0", "-Wall", "-Wextra", "-Werror",
                  "-Wno-unused-parameter", "-Wno-sign-compare", "-Wno-pointer-sign",
                  "-ffreestanding", "-fno-builtin", "-fno-strict-aliasing", "-fno-common",
                  "-fno-pic", "-fno-PIE", "-fno-stack-protector", "-fno-unwind-tables",
                  "-fno-asynchronous-unwind-tables", "-mgeneral-regs-only", "-march=armv8-a",
                  "-mno-outline-atomics"]
        if clang:
            cflags += ["-Wno-gnu-variable-sized-type-not-at-end"]
        commands = []
        objects = []
        for name in SOURCES:
            source = ROOT / "src" / name
            obj = build / (source.stem + ("_asm" if source.suffix == ".S" else "") + ".o")
            flags = common + (["-D__ASSEMBLY__", "-march=armv8-a"] if source.suffix == ".S" else cflags)
            command = compiler + flags + ["-c", str(source), "-o", str(obj)]
            print(f"CC {name}", flush=True)
            subprocess.run(command, check=True)
            commands.append(command)
            objects.append(obj)
        destination = dist / "selimirror.kpm"
        command = linker + ["-r", "-o", str(destination)] + [str(obj) for obj in objects]
        subprocess.run(command, check=True)
        commands.append(command)
        result = audit(destination)
        manifest = {
            "module": "selimirror", "version": "0.1.0",
            "kernel_source": "https://github.com/Laulan56/android_kernel_xiaomi_sm8150",
            "kernel_commit": KERNEL_COMMIT, "kernel_release": release,
            "config_sha256": config_sha,
            "autoconf_sha256": digest(out / "include/generated/autoconf.h"),
            "compiler": version, "linker": linker_version,
            "artifact_sha256": digest(destination), "elf_audit": result,
            "validation_scope": "cross-compile and static ELF audit; no device result implied",
        }
        (dist / "build-manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
        # Keep exact argument boundaries; no shell quoting or execution on replay.
        (build / "commands.json").write_text(json.dumps(commands, indent=2) + "\n")
        print(f"PASS: {destination.name}, {result['bytes']} bytes, {len(result['imports'])} expected imports")
        print(f"SHA256: {manifest['artifact_sha256']}")
    except (OSError, ValueError, subprocess.CalledProcessError) as error:
        parser.exit(1, f"Build failed: {error}\n")


if __name__ == "__main__":
    main()
