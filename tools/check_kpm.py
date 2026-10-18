#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Audit a final KPM using the ELF ABI supported by the pinned KP loader."""
import argparse
import json
import struct
from pathlib import Path

ALLOWED_IMPORTS = {
    "kallsyms_lookup_name", "kpver", "symbol_lookup_name",
    "hook_wrap", "hook_unwrap_remove", "compat_copy_to_user",
}
# KernelPatch ef52c62, kernel/patch/module/relo.c, apply_relocate_add().
ALLOWED_RELOCS = set(range(257, 281)) | set(range(282, 294)) | {299}
# Reserved 281 and TLS/GOT/dynamic relocations are intentionally absent.
REQUIRED_SECTIONS = (".kpm.info", ".kpm.init", ".kpm.ctl0", ".kpm.exit")


def audit(path):
    data = Path(path).read_bytes()
    if len(data) < 64:
        raise ValueError("truncated ELF header")
    hdr = struct.unpack_from("<16sHHIQQQIHHHHHH", data)
    if hdr[0][:7] != b"\x7fELF\x02\x01\x01" or hdr[1:3] != (1, 183):
        raise ValueError("expected ELF64 little-endian AArch64 ET_REL")
    if hdr[11] != 64 or not hdr[12] or hdr[13] >= hdr[12]:
        raise ValueError("unsupported section table")
    if hdr[6] + hdr[11] * hdr[12] > len(data):
        raise ValueError("section table is outside file")
    sections = [struct.unpack_from("<IIQQQQIIQQ", data, hdr[6] + i * 64)
                for i in range(hdr[12])]

    def payload(section):
        if section[1] == 8:
            return b""
        start, size = section[4:6]
        if start + size > len(data):
            raise ValueError("section payload is outside file")
        return data[start:start + size]

    strings = payload(sections[hdr[13]])

    def cstring(table, offset):
        if offset >= len(table):
            raise ValueError("invalid string offset")
        end = table.find(b"\0", offset)
        if end < 0:
            raise ValueError("unterminated ELF string")
        return table[offset:end].decode("ascii")

    named = {cstring(strings, section[0]): section for section in sections}
    for name in REQUIRED_SECTIONS:
        if name not in named or not named[name][2] & 2:
            raise ValueError(f"missing allocated {name}")
    for name in REQUIRED_SECTIONS[1:]:
        if named[name][5] != 8:
            raise ValueError(f"{name} must contain exactly one function pointer")
    banned = {".interp", ".dynamic", ".dynsym", ".plt", ".got", ".got.plt", ".init_array"}
    if banned & named.keys():
        raise ValueError(f"userspace linker sections: {sorted(banned & named.keys())}")
    # .llvm_addrsig is a harmless non-allocated address-significance table,
    # not LLVM bitcode.  Only reject actual LTO payloads here.
    if any(name.startswith((".llvmbc", ".llvm.lto", ".gnu.lto")) for name in named):
        raise ValueError("LTO sections are unsupported")

    imports = set()
    for section in sections:
        if section[1] != 2:
            continue
        if section[9] != 24 or section[5] % 24 or section[6] >= len(sections):
            raise ValueError("invalid symbol table")
        symstrings = payload(sections[section[6]])
        symbols = payload(section)
        for offset in range(0, len(symbols), 24):
            name, _, _, index, _, _ = struct.unpack_from("<IBBHQQ", symbols, offset)
            if index == 0 and name:
                imports.add(cstring(symstrings, name))
    if imports != ALLOWED_IMPORTS:
        raise ValueError(f"unexpected imports: extra={sorted(imports - ALLOWED_IMPORTS)}, "
                         f"missing={sorted(ALLOWED_IMPORTS - imports)}")

    relocations = 0
    relocation_types = set()
    for section in sections:
        if section[1] == 9:
            raise ValueError("REL relocations unsupported; expected RELA")
        if section[1] != 4:
            continue
        if section[9] != 24 or section[5] % 24:
            raise ValueError("invalid relocation section")
        for offset in range(0, section[5], 24):
            _, info, _ = struct.unpack_from("<QQq", payload(section), offset)
            kind = info & 0xffffffff
            if kind not in ALLOWED_RELOCS:
                raise ValueError(f"unsupported AArch64 relocation {kind}")
            relocation_types.add(kind)
            relocations += 1
    metadata = {}
    for entry in payload(named[".kpm.info"]).split(b"\0"):
        if entry:
            key, value = entry.decode("utf-8").split("=", 1)
            if key in metadata:
                raise ValueError(f"duplicate metadata {key}")
            metadata[key] = value
    if metadata.get("name") != "selimirror" or metadata.get("license") != "GPL v2":
        raise ValueError("unexpected module identity or license")
    return {
        "format": "ELF64 little-endian AArch64 ET_REL",
        "bytes": len(data), "metadata": metadata,
        "imports": sorted(imports), "relocations": relocations,
        "relocation_types": sorted(relocation_types),
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("file", type=Path)
    args = parser.parse_args()
    try:
        print(json.dumps(audit(args.file), indent=2))
    except (OSError, ValueError, struct.error, UnicodeError) as error:
        parser.exit(1, f"KPM audit failed: {error}\n")


if __name__ == "__main__":
    main()
