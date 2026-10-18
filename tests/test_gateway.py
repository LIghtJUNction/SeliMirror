#!/usr/bin/env python3
"""Execute the actual AArch64 gateway template with Unicorn.

Install test dependencies:
  python3 -m pip install unicorn==2.1.4 capstone==5.0.9 pyelftools==0.33
Run after compiling src/gateway.S:
  python3 tests/test_gateway.py --object build/gateway_asm.o

These tests execute the emitted instructions. Competing CPU stores are modeled
by injecting a failed store-exclusive, as ARM64 requires after that race. This
does not replace tests on the target kernel or its memory-ordering hardware.
"""

import argparse
import struct
import sys
import unittest
from pathlib import Path

from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM
from elftools.elf.elffile import ELFFile
from unicorn import Uc, UC_ARCH_ARM64, UC_MODE_ARM, UC_HOOK_CODE, UC_HOOK_MEM_READ
from unicorn.arm64_const import (
    UC_ARM64_REG_PC,
    UC_ARM64_REG_SP,
    UC_ARM64_REG_X0,
    UC_ARM64_REG_X1,
    UC_ARM64_REG_X18,
    UC_ARM64_REG_X19,
    UC_ARM64_REG_X28,
    UC_ARM64_REG_X29,
    UC_ARM64_REG_X30,
    UC_ARM64_REG_W11,
)

parser = argparse.ArgumentParser(add_help=False)
parser.add_argument("--object", type=Path, default=Path("build/gateway_asm.o"))
options, unittest_args = parser.parse_known_args()

CLOSED = 1 << 63
STATE_OFFSET = 128
HANDLER_OFFSET = 136
CONTEXT_OFFSET = 144
STRIDE = 192
CODE = 0x100000
HANDLER = 0x400000
STOP = 0x500000
STACK = 0x800000
ARGS = 0xA00000
PRIVATE_CONTEXT = 0xB00000
PAGE = 4096


def unpack64(value):
    return struct.unpack("<Q", value)[0]


def pack64(value):
    return struct.pack("<Q", value)


class Machine:
    def __init__(self, template, slot=0, count=0, handler=HANDLER):
        self.uc = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
        self.uc.mem_map(CODE, PAGE)
        self.uc.mem_map(HANDLER, PAGE)
        self.uc.mem_map(STOP, PAGE)
        self.uc.mem_map(STACK, 16 * PAGE)
        self.uc.mem_map(ARGS, PAGE)
        self.entry = CODE + slot * STRIDE
        self.uc.mem_write(self.entry, template)
        self.set_count(count)
        self.uc.mem_write(self.entry + HANDLER_OFFSET, pack64(handler))
        self.uc.mem_write(self.entry + CONTEXT_OFFSET, pack64(PRIVATE_CONTEXT))
        # Clobber scratch registers, including the state register x16, then RET.
        # The gateway must restore its own saved x16 and caller's x29/x30/SP.
        self.uc.mem_write(HANDLER, bytes.fromhex(
            "100080d2"  # mov x16, #0
            "110080d2"  # mov x17, #0
            "090080d2"  # mov x9, #0
            "000080d2"  # mov x0, #0
            "c0035fd6"  # ret
        ))
        self.calls = []
        self.reads = []
        self.on_instruction = None
        self.on_handler = None
        self.uc.hook_add(UC_HOOK_CODE, self._code)
        self.uc.hook_add(UC_HOOK_MEM_READ, self._read)
        self.original_sp = STACK + 15 * PAGE
        self.preserved = {
            UC_ARM64_REG_X18: 0x1818181818181818,
            UC_ARM64_REG_X19: 0x1919191919191919,
            UC_ARM64_REG_X28: 0x2828282828282828,
            UC_ARM64_REG_X29: 0x2929292929292929,
        }

    def _code(self, uc, address, size, user_data):
        if self.on_instruction:
            self.on_instruction(self, address)
        if address == HANDLER:
            self.calls.append((uc.reg_read(UC_ARM64_REG_X0),
                               uc.reg_read(UC_ARM64_REG_X1), self.count()))
            if self.on_handler:
                self.on_handler(self)

    def _read(self, uc, access, address, size, value, user_data):
        self.reads.append((address, size))

    def count(self):
        return unpack64(self.uc.mem_read(self.entry + STATE_OFFSET, 8))

    def set_count(self, count):
        self.uc.mem_write(self.entry + STATE_OFFSET, pack64(count))

    def close(self):
        self.set_count(self.count() | CLOSED)

    def erase_module_pointers(self):
        self.uc.mem_write(self.entry + HANDLER_OFFSET, pack64(0))
        self.uc.mem_write(self.entry + CONTEXT_OFFSET, pack64(0))

    def invoke(self, upstream_context=0):
        self.uc.reg_write(UC_ARM64_REG_X0, ARGS)
        self.uc.reg_write(UC_ARM64_REG_X1, upstream_context)
        self.uc.reg_write(UC_ARM64_REG_SP, self.original_sp)
        self.uc.reg_write(UC_ARM64_REG_X30, STOP)
        for register, value in self.preserved.items():
            self.uc.reg_write(register, value)
        self.uc.emu_start(self.entry, STOP, count=10000)
        if self.uc.reg_read(UC_ARM64_REG_PC) != STOP:
            raise AssertionError("gateway did not return within instruction bound")
        if self.uc.reg_read(UC_ARM64_REG_SP) != self.original_sp:
            raise AssertionError("gateway did not restore the stack")
        for register, value in self.preserved.items():
            if self.uc.reg_read(register) != value:
                raise AssertionError("gateway clobbered a preserved register")


class GatewayInstructions(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        with options.object.open("rb") as source:
            elf = ELFFile(source)
            if elf["e_machine"] != "EM_AARCH64":
                raise AssertionError("gateway object must be AArch64")
            section = elf.get_section_by_name(".rodata.kp_gate")
            if section is None:
                raise AssertionError("gateway template section missing")
            cls.template = section.data()
            cls.template_section_index = elf.get_section_index(".rodata.kp_gate")
            cls.relocations = [
                s.name for s in elf.iter_sections()
                if s["sh_type"] in ("SHT_RELA", "SHT_REL")
                and s["sh_info"] == cls.template_section_index and s.num_relocations()
            ]
        cls.instructions = list(Cs(CS_ARCH_ARM64, CS_MODE_ARM).disasm(
            cls.template[:STATE_OFFSET], 0))
        cls.call_offset = next(i.address for i in cls.instructions if i.mnemonic == "blr")
        cls.store_offsets = [i.address for i in cls.instructions if i.mnemonic == "stlxr"]
        cls.handler_load_offset = next(i.address for i in cls.instructions
                                       if i.mnemonic == "ldr" and i.op_str.startswith("x17,"))

    def test_template_has_exact_size_and_no_relocations(self):
        self.assertEqual(len(self.template), STRIDE)
        self.assertEqual(self.relocations, [])
        self.assertEqual(self.template[STATE_OFFSET:CONTEXT_OFFSET + 8], bytes(24))
        self.assertEqual(len(self.store_offsets), 2)

    def test_open_gate_preserves_arguments_and_ignores_upstream_context(self):
        m = Machine(self.template)
        m.invoke(upstream_context=0xDEAD0000)
        self.assertEqual(m.calls, [(ARGS, PRIVATE_CONTEXT, 1)])
        self.assertEqual(m.count(), 0)

    def test_copied_gate_uses_its_own_state(self):
        m = Machine(self.template, slot=7)
        m.invoke()
        self.assertEqual(m.calls, [(ARGS, PRIVATE_CONTEXT, 1)])
        self.assertEqual(m.count(), 0)
        self.assertEqual(unpack64(m.uc.mem_read(CODE + STATE_OFFSET, 8)), 0)

    def test_closed_gate_never_reads_module_pointers(self):
        m = Machine(self.template, count=CLOSED, handler=0xDEAD0000)
        m.invoke()
        self.assertEqual(m.calls, [])
        self.assertEqual(m.count(), CLOSED)
        protected = (m.entry + HANDLER_OFFSET, m.entry + CONTEXT_OFFSET)
        self.assertFalse(any(address in protected for address, _ in m.reads))

    def test_already_admitted_call_stays_counted_after_close(self):
        m = Machine(self.template)
        def close_before_pointer_load(machine, address):
            if address == machine.entry + self.handler_load_offset:
                self.assertEqual(machine.count(), 1)
                machine.close()
        m.on_instruction = close_before_pointer_load
        m.invoke()
        self.assertEqual(m.calls, [(ARGS, PRIVATE_CONTEXT, CLOSED | 1)])
        self.assertEqual(m.count(), CLOSED)

    def test_close_inside_handler_preserves_closed_flag_on_return(self):
        m = Machine(self.template)
        m.on_handler = lambda machine: machine.close()
        m.invoke()
        self.assertEqual(m.count(), CLOSED)
        self.assertEqual(len(m.calls), 1)

    def test_counter_released_only_after_return_to_resident_code(self):
        m = Machine(self.template)
        def returned(machine, address):
            if address == machine.entry + self.call_offset + 4:
                self.assertEqual(len(machine.calls), 1)
                self.assertEqual(machine.count(), 1)
                machine.close()
        m.on_instruction = returned
        m.invoke()
        self.assertEqual(m.count(), CLOSED)

    def test_competing_close_invalidates_admission_store(self):
        m = Machine(self.template)
        failures = []
        def compete(machine, address):
            if address == machine.entry + self.store_offsets[0] and not failures:
                failures.append(address)
                machine.close()
                # A peer's write invalidates the exclusive reservation. Inject
                # the architectural failed-STLXR result and resume its retry.
                machine.uc.reg_write(UC_ARM64_REG_W11, 1)
                machine.uc.reg_write(UC_ARM64_REG_PC, address + 4)
        m.on_instruction = compete
        m.invoke()
        self.assertEqual(len(failures), 1)
        self.assertEqual(m.calls, [])
        self.assertEqual(m.count(), CLOSED)

    def test_admission_retries_failed_store_without_losing_the_call(self):
        m = Machine(self.template)
        failures = []
        def fail_once(machine, address):
            if address == machine.entry + self.store_offsets[0] and not failures:
                failures.append(address)
                machine.uc.reg_write(UC_ARM64_REG_W11, 1)
                machine.uc.reg_write(UC_ARM64_REG_PC, address + 4)
        m.on_instruction = fail_once
        m.invoke()
        self.assertEqual(m.calls, [(ARGS, PRIVATE_CONTEXT, 1)])
        self.assertEqual(m.count(), 0)

    def test_release_retries_competing_close_without_losing_closed_flag(self):
        m = Machine(self.template)
        failures = []
        def close_before_release_store(machine, address):
            if address == machine.entry + self.store_offsets[1] and not failures:
                failures.append(address)
                self.assertEqual(machine.count(), 1)
                machine.close()
                machine.uc.reg_write(UC_ARM64_REG_W11, 1)
                machine.uc.reg_write(UC_ARM64_REG_PC, address + 4)
        m.on_instruction = close_before_release_store
        m.invoke()
        self.assertEqual(len(m.calls), 1)
        self.assertEqual(m.count(), CLOSED)

    def test_other_active_calls_are_preserved(self):
        m = Machine(self.template, count=5)
        m.invoke()
        self.assertEqual(m.calls, [(ARGS, PRIVATE_CONTEXT, 6)])
        self.assertEqual(m.count(), 5)

    def test_stale_entry_after_close_drain_and_pointer_erasure(self):
        m = Machine(self.template)
        m.invoke()
        m.close()
        self.assertEqual(m.count(), CLOSED)
        m.erase_module_pointers()
        m.uc.mem_unmap(HANDLER, PAGE)
        m.calls.clear()
        m.reads.clear()
        m.invoke(upstream_context=0)
        self.assertEqual(m.calls, [])
        self.assertEqual(m.count(), CLOSED)
        protected = (m.entry + HANDLER_OFFSET, m.entry + CONTEXT_OFFSET)
        self.assertFalse(any(address in protected for address, _ in m.reads))

    def test_null_handler_still_releases_admission(self):
        m = Machine(self.template, handler=0)
        m.invoke()
        self.assertEqual(m.calls, [])
        self.assertEqual(m.count(), 0)


if __name__ == "__main__":
    unittest.main(argv=[sys.argv[0], *unittest_args])
