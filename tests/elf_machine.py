#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Small AArch64 ET_REL runner for the production KPM integration tests.

This is a test loader, not a replacement for the KernelPatch loader. Only the
relocation kinds emitted by this project's audited build are accepted. Kernel
and KernelPatch calls can be stubbed; defined module functions are never
replaced. Unknown imports or relocation kinds fail the test.
"""

import io

from elftools.elf.elffile import ELFFile
from unicorn import Uc, UcError, UC_ARCH_ARM64, UC_MODE_ARM, UC_HOOK_CODE
from unicorn.arm64_const import (
    UC_ARM64_REG_PC, UC_ARM64_REG_PSTATE, UC_ARM64_REG_SP,
    UC_ARM64_REG_X0, UC_ARM64_REG_X1, UC_ARM64_REG_X2, UC_ARM64_REG_X3,
    UC_ARM64_REG_X4, UC_ARM64_REG_X5, UC_ARM64_REG_X6, UC_ARM64_REG_X7,
    UC_ARM64_REG_X30,
)

PAGE = 4096
MASK64 = (1 << 64) - 1
ARG_REGS = (UC_ARM64_REG_X0, UC_ARM64_REG_X1, UC_ARM64_REG_X2,
            UC_ARM64_REG_X3, UC_ARM64_REG_X4, UC_ARM64_REG_X5,
            UC_ARM64_REG_X6, UC_ARM64_REG_X7)


def align(value, alignment=PAGE):
    return (value + alignment - 1) & -alignment


def signed(value, bits=64):
    value &= (1 << bits) - 1
    return value - (1 << bits) if value & (1 << (bits - 1)) else value


class ElfMachine:
    MODULE_BASE = 0x100000
    MODULE_LIMIT = 0x200000
    STUB_BASE = 0x400000
    STOP = 0x500000
    HEAP_BASE = 0x1000000
    STACK_BASE = 0x7000000
    STACK_SIZE = 0x100000

    def __init__(self):
        self.uc = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
        self.uc.mem_map(self.STUB_BASE, 0x10000)
        self.uc.mem_map(self.STOP, PAGE)
        self.uc.mem_map(self.STACK_BASE, self.STACK_SIZE)
        # EL1h keeps the emulated task pointer in SP_EL0 separate from SP.
        self.uc.reg_write(UC_ARM64_REG_PSTATE, 0x3C5)
        self.next_stub = self.STUB_BASE
        self.next_heap = self.HEAP_BASE
        self.stubs = {}
        self.allocations = {}
        self.symbols = {}
        self.symbol_sizes = {}
        self.sections = {}
        self.watches = {}
        self.uc.hook_add(UC_HOOK_CODE, self._instruction)

    def read(self, address, length):
        return bytes(self.uc.mem_read(address, length))

    def write(self, address, data):
        self.uc.mem_write(address, bytes(data))

    def uint(self, address, size=8):
        return int.from_bytes(self.read(address, size), "little")

    def put(self, address, value, size=8):
        self.write(address, (value & ((1 << (8 * size)) - 1)).to_bytes(size, "little"))

    def cstring(self, address, limit=8192):
        if not address:
            return "(null)"
        data = bytearray()
        for offset in range(limit):
            byte = self.uint(address + offset, 1)
            if not byte:
                return data.decode("utf-8")
            data.append(byte)
        raise AssertionError("unterminated emulated string")

    def allocate(self, size, kind="fixture", data=b""):
        size = max(size, len(data), 1)
        address = self.next_heap
        mapped = align(size)
        self.next_heap += mapped + PAGE
        self.uc.mem_map(address, mapped)
        if data:
            self.write(address, data)
        self.allocations[address] = {
            "size": size, "mapped": mapped, "kind": kind, "freed": False,
        }
        return address

    def string(self, text):
        data = text.encode("utf-8") + b"\0"
        return self.allocate(len(data), data=data)

    def free(self, address):
        if not address:
            return
        item = self.allocations[address]
        if item["freed"]:
            raise AssertionError("double free in production module")
        self.uc.mem_unmap(address, item["mapped"])
        item["freed"] = True

    def stub(self, name, callback):
        address = self.next_stub
        self.next_stub += 16
        if self.next_stub >= self.STUB_BASE + 0x10000:
            raise AssertionError("too many native test stubs")
        self.write(address, bytes.fromhex("c0035fd6"))  # RET, never reached.
        self.stubs[address] = (name, callback)
        return address

    def argument(self, index):
        if index < 8:
            return self.uc.reg_read(ARG_REGS[index])
        return self.uint(self.uc.reg_read(UC_ARM64_REG_SP) + 8 * (index - 8))

    def _instruction(self, uc, address, size, user_data):
        if address in self.watches:
            self.watches[address]()
        if address in self.stubs:
            _, callback = self.stubs[address]
            result = callback()
            uc.reg_write(UC_ARM64_REG_X0, (result or 0) & MASK64)
            uc.reg_write(UC_ARM64_REG_PC, uc.reg_read(UC_ARM64_REG_X30))

    def load(self, path, imports):
        elf = ELFFile(io.BytesIO(path.read_bytes()))
        if (elf["e_type"], elf["e_machine"], elf.little_endian) != (
                "ET_REL", "EM_AARCH64", True):
            raise AssertionError("expected a little-endian AArch64 ET_REL KPM")
        cursor = self.MODULE_BASE
        bases = {}
        for index, section in enumerate(elf.iter_sections()):
            if not section["sh_flags"] & 2:
                continue
            cursor = align(cursor, max(PAGE, section["sh_addralign"]))
            bases[index] = cursor
            self.sections[section.name] = cursor
            cursor += align(max(section["sh_size"], 1))
        self.module_bytes = cursor - self.MODULE_BASE
        if cursor > self.MODULE_BASE + self.MODULE_LIMIT:
            raise AssertionError("test module mapping capacity exceeded")
        self.uc.mem_map(self.MODULE_BASE, self.module_bytes)
        for index, base in bases.items():
            section = elf.get_section(index)
            if section["sh_type"] != "SHT_NOBITS":
                self.write(base, section.data())

        symtab = elf.get_section_by_name(".symtab")
        if not symtab:
            raise AssertionError("production KPM must retain its symbol table")

        def symbol_address(symbol):
            index = symbol["st_shndx"]
            if index == "SHN_UNDEF":
                if symbol.name not in imports:
                    raise AssertionError(f"unmodeled KPM import: {symbol.name}")
                return imports[symbol.name]
            if index == "SHN_ABS":
                return symbol["st_value"]
            if index not in bases:
                raise AssertionError(f"relocation into unallocated section: {symbol.name}")
            return bases[index] + symbol["st_value"]

        for symbol in symtab.iter_symbols():
            if symbol["st_shndx"] in bases and symbol.name:
                self.symbols[symbol.name] = symbol_address(symbol)
                self.symbol_sizes[symbol.name] = symbol["st_size"]

        self.relocation_types = set()
        for section in elf.iter_sections():
            if section["sh_type"] != "SHT_RELA" or section["sh_info"] not in bases:
                continue
            for relocation in section.iter_relocations():
                kind = relocation["r_info_type"]
                self.relocation_types.add(kind)
                place = bases[section["sh_info"]] + relocation["r_offset"]
                target = symbol_address(symtab.get_symbol(relocation["r_info_sym"]))
                target += relocation["r_addend"]
                self._relocate(kind, place, target)

        for section, symbol in ((".kpm.init", "rsk_init"),
                                (".kpm.ctl0", "rsk_control"),
                                (".kpm.exit", "rsk_exit")):
            if self.uint(self.sections[section]) != self.symbols[symbol]:
                raise AssertionError(f"incorrect relocated entry in {section}")

    def _relocate(self, kind, place, target):
        if kind == 257:  # R_AARCH64_ABS64
            self.put(place, target)
            return
        instruction = self.uint(place, 4)
        if kind in (282, 283):  # JUMP26, CALL26
            offset = target - place
            if offset & 3 or not -(1 << 27) <= offset < (1 << 27):
                raise AssertionError("branch relocation out of range")
            instruction = (instruction & ~0x3FFFFFF) | ((offset >> 2) & 0x3FFFFFF)
        elif kind == 275:  # ADR_PREL_PG_HI21
            pages = ((target & -PAGE) - (place & -PAGE)) >> 12
            if not -(1 << 20) <= pages < (1 << 20):
                raise AssertionError("ADRP relocation out of range")
            immediate = pages & 0x1FFFFF
            instruction &= ~((3 << 29) | (0x7FFFF << 5))
            instruction |= ((immediate & 3) << 29) | ((immediate >> 2) << 5)
        elif kind in (277, 278, 284, 285, 286):  # ADD / LDST low 12 bits
            scale = {277: 0, 278: 0, 284: 1, 285: 2, 286: 3}[kind]
            if target & ((1 << scale) - 1):
                raise AssertionError("unaligned load/store relocation")
            immediate = (target & 0xFFF) >> scale
            instruction = (instruction & ~(0xFFF << 10)) | (immediate << 10)
        else:
            raise AssertionError(f"unmodeled AArch64 relocation {kind}")
        self.put(place, instruction, 4)

    def global_value(self, name):
        return self.uint(self.symbols[name], self.symbol_sizes[name])

    def call(self, entry, *arguments):
        address = self.symbols[entry] if isinstance(entry, str) else entry
        stack = self.STACK_BASE + self.STACK_SIZE - PAGE
        self.uc.reg_write(UC_ARM64_REG_SP, stack)
        self.uc.reg_write(UC_ARM64_REG_X30, self.STOP)
        for index, value in enumerate(arguments):
            if index < 8:
                self.uc.reg_write(ARG_REGS[index], value & MASK64)
            else:
                self.put(stack + (index - 8) * 8, value)
        try:
            self.uc.emu_start(address, self.STOP, count=500000)
        except UcError as error:
            pc = self.uc.reg_read(UC_ARM64_REG_PC)
            raise AssertionError(f"emulation failed at {pc:#x}: {error}") from error
        if self.uc.reg_read(UC_ARM64_REG_PC) != self.STOP:
            raise AssertionError("production call exceeded instruction bound")
        if self.uc.reg_read(UC_ARM64_REG_SP) != stack:
            raise AssertionError("production call did not restore SP")
        return signed(self.uc.reg_read(UC_ARM64_REG_X0))
