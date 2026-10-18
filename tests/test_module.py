#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Execute the production KPM's ARM64 lifecycle and callbacks with native mocks.

  python3 -m pip install unicorn==2.1.4 pyelftools==0.33
  python3 tests/test_module.py --module dist/selimirror.kpm -v

The real ELF is relocated, and its init/control/exit, policy wrapper, query
logic, and resident gateways execute unchanged. Only external KernelPatch and
kernel functions are mocked. In particular policydb_read/load_isids are MOCKS:
these tests do not execute Linux's SELinux parser, the KP patching machinery,
RCU, or concurrent CPUs, and do not establish a Hunter/device test result.

The native data fixtures below were measured with offsetof/sizeof probes from
the pinned kernel and the recorded build configuration. Other configurations
require fresh native layout probes, not guessing new offsets.
"""

import argparse
import re
import struct
import unittest
from pathlib import Path

from unicorn.arm64_const import UC_ARM64_REG_SP_EL0

from elf_machine import ElfMachine, PAGE, signed

parser = argparse.ArgumentParser(add_help=False)
parser.add_argument("--module", type=Path,
                    default=Path("dist/selimirror.kpm"))
options, unittest_args = parser.parse_known_args()

FIXTURE_CONFIG = "f2feadf62787fa1b7acccce254e3bb25348e61c8025266a0ed1b41a58d3e1bd9"
FIXTURE_RELEASE = "4.14.268-perf-gbd65f57d4c36"
FIXTURE_KERNEL = "bd65f57d4c36882a5dfd34557e64198516ed392b"
# Native probes, CONFIG_SECURITY_SELINUX_DEVELOP=y, queued rwlock size 8.
ABI = {
    "state_size": 32, "state_initialized": 3, "state_enforcing": 1,
    "state_avc": 16, "state_ss": 24, "ss_size": 576,
    "ss_policydb": 8, "policydb_size": 496, "sidtab_size": 7176,
    "file_size": 256, "file_inode": 32, "inode_mode": 0, "inode_size": 80,
    "task_cred": 2048, "cred_uid": 4, "cred_security": 120,
    "task_security_sid": 4,
}
GATE_STRIDE = 192
GATE_STATE = 128
CLOSED = 1 << 63
FA_SKIP = 8
FA_RET = 80
FA_ARG0 = 88
QUERY_HOOKS = ("sel_write_context", "sel_write_access",
               "selinux_setprocattr", "selinux_kernel_status_page")


class ModuleMachine(ElfMachine):
    """A deliberately small external kernel model; module code stays real."""

    def __init__(self, initialized=True, missing=(), hook_failure=None,
                 parser_error=0, isids_error=0, allocation_failure=None):
        super().__init__()
        self.events = []
        self.logs = []
        self.missing = set(missing)
        self.hook_failure = hook_failure
        self.parser_error = parser_error
        self.isids_error = isids_error
        self.allocation_failure = allocation_failure
        self.hook_attempts = []
        self.hooks = {}
        self.copy_short = False
        self.open_error = 0
        self.permission_error = 0
        self.complete_during_sleep = False
        self.file_data = b"MOCK POLICY INPUT: native parser is stubbed\n"
        self.canonical = b"u:r:untrusted_app:s0\0"
        self.context_calls = []
        self.native = {}

        if FIXTURE_CONFIG.encode() not in options.module.read_bytes():
            raise AssertionError("KPM does not match the probed native fixture configuration")
        self.live_state = self.allocate(ABI["state_size"])
        self.put(self.live_state + ABI["state_initialized"], int(initialized), 1)
        self.put(self.live_state + ABI["state_enforcing"], 1, 1)
        self.put(self.live_state + ABI["state_avc"], self.allocate(64))
        self.put(self.live_state + ABI["state_ss"], self.allocate(ABI["ss_size"]))
        self.native["selinux_state"] = self.live_state
        self.native["linux_banner"] = self.string(f"Linux version {FIXTURE_RELEASE} (mock build)\n")

        self.file = self.allocate(ABI["file_size"])
        self.inode = self.allocate(1024)
        self.put(self.file + ABI["file_inode"], self.inode)
        self.put(self.inode + ABI["inode_mode"], 0o100600, 2)
        self.put(self.inode + ABI["inode_size"], len(self.file_data))

        self.task = self.allocate(ABI["task_cred"] + 256)
        self.cred = self.allocate(256)
        self.security = self.allocate(24)
        self.put(self.task + ABI["task_cred"], self.cred)
        self.put(self.cred + ABI["cred_security"], self.security)
        self.put(self.security + ABI["task_security_sid"], 33, 4)
        self.set_uid(10000)
        self.uc.reg_write(UC_ARM64_REG_SP_EL0, self.task)

        task_offsets = self.allocate(34)
        cred_offsets = self.allocate(54)
        # KP ABI arrays contain signed 16-bit offsets, not native structures.
        self.put(task_offsets + 5 * 2, ABI["task_cred"], 2)
        self.put(cred_offsets + 3 * 2, ABI["cred_uid"], 2)
        self.put(cred_offsets + 25 * 2, ABI["cred_security"], 2)
        self.kp_symbols = {"task_struct_offset": task_offsets, "cred_offset": cred_offsets}

        callbacks = {
            "printk": self._printk,
            "__kmalloc": lambda: self._allocate_native("kmalloc"),
            "vmalloc": lambda: self._allocate_native("vmalloc"),
            "vmalloc_user": lambda: self._allocate_native("vmalloc_user"),
            "module_alloc": lambda: self._allocate_native("module_alloc"),
            "kfree": lambda: self._free_native("kfree"),
            "vfree": lambda: self._free_native("vfree"),
            "vmalloc_to_page": self._to_page,
            "memset": self._memset,
            "memcpy": self._memcpy,
            "snprintf": self._snprintf,
            "policydb_read": self._policydb_read,
            "policydb_destroy": lambda: self._record("policydb_destroy"),
            "policydb_load_isids": self._load_isids,
            "sidtab_destroy": lambda: self._record("sidtab_destroy"),
            "security_context_to_sid": self._context_to_sid,
            "security_sid_to_context": self._sid_to_context,
            "security_compute_av_user": self._compute_av,
            "avc_has_perm": self._permission,
            "filp_open": self._open,
            "filp_close": lambda: self._record("filp_close"),
            "kernel_read": self._read_file,
            "__flush_icache_range": lambda: self._record("flush_icache"),
            "kick_all_cpus_sync": lambda: self._record("kick_cpus"),
            "msleep": self._sleep,
            "synchronize_rcu": lambda: self._record("synchronize_rcu"),
        }
        for name, callback in callbacks.items():
            self.native[name] = self.stub(name, callback)
        for name in QUERY_HOOKS + ("security_load_policy",):
            self.native[name] = self.stub(name, self._unexpected_original)
        self.native_names = {address: name for name, address in self.native.items()}

        kpver = self.allocate(4)
        self.put(kpver, 0x000D09, 4)
        lookup_pointer = self.allocate(8)
        self.put(lookup_pointer, self.stub("native_lookup", self._native_lookup))
        imports = {
            "kpver": kpver,
            "kallsyms_lookup_name": lookup_pointer,
            "symbol_lookup_name": self.stub("kp_lookup", self._kp_lookup),
            "hook_wrap": self.stub("hook_wrap", self._hook_wrap),
            "hook_unwrap_remove": self.stub("hook_remove", self._hook_remove),
            "compat_copy_to_user": self.stub("copy_to_user", self._copy_to_user),
        }
        self.load(options.module, imports)
        for name in ("kp_gate_close_all", "kp_gate_drain", "kp_gate_pool_release",
                     "rsk_policy_destroy"):
            self.watches[self.symbols[name]] = lambda name=name: self.events.append((name,))

    def _record(self, name):
        self.events.append((name, self.argument(0)))
        return 0

    def names(self):
        return [event[0] for event in self.events]

    def set_uid(self, uid):
        self.put(self.cred + ABI["cred_uid"], uid, 4)

    def _native_lookup(self):
        name = self.cstring(self.argument(0))
        self.events.append(("lookup", name))
        return 0 if name in self.missing else self.native.get(name, 0)

    def _kp_lookup(self):
        return self.kp_symbols.get(self.cstring(self.argument(0)), 0)

    def _allocate_native(self, kind):
        if self.allocation_failure == kind:
            return 0
        address = self.allocate(self.argument(0), kind)
        self.events.append(("allocate", kind, address))
        return address

    def _free_native(self, operation):
        address = self.argument(0)
        kind = self.allocations[address]["kind"] if address else "null"
        self.events.append((operation, address, kind))
        self.free(address)
        return 0

    def _to_page(self):
        if self.allocation_failure == "vmalloc_to_page":
            return 0
        return self.allocate(64, "page_descriptor")

    def _memset(self):
        destination, value, size = (self.argument(i) for i in range(3))
        self.write(destination, bytes([value & 0xFF]) * size)
        return destination

    def _memcpy(self):
        destination, source, size = (self.argument(i) for i in range(3))
        self.write(destination, self.read(source, size))
        return destination

    def _format(self, format_address, first_argument):
        text = self.cstring(format_address)
        index = first_argument

        def replace(match):
            nonlocal index
            if match.group(0) == "%%":
                return "%"
            length, conversion = match.groups()
            value = self.argument(index)
            index += 1
            if conversion == "s":
                return self.cstring(value)
            bits = 64 if length else 32
            if conversion == "d":
                return str(signed(value, bits))
            value &= (1 << bits) - 1
            return format(value, "x") if conversion == "x" else str(value)

        rendered = re.sub(r"%(ll|l|z)?([sdux])|%%", replace, text)
        if re.search(r"%(?:[0-9.*#-]|[a-zA-Z])", rendered):
            raise AssertionError(f"unmodeled kernel format string: {text!r}")
        return rendered.encode("utf-8")

    def _printk(self):
        output = self._format(self.argument(0), 1)
        self.logs.append(output.decode("utf-8"))
        return len(output)

    def _snprintf(self):
        destination, capacity = self.argument(0), self.argument(1)
        data = self._format(self.argument(2), 3)
        if capacity:
            self.write(destination, data[:capacity - 1] + b"\0")
        return len(data)

    def _policydb_read(self):
        policydb, policy_file = self.argument(0), self.argument(1)
        data, length = self.uint(policy_file), self.uint(policy_file + 8)
        self.events.append(("policydb_read", policydb, self.read(data, length)))
        # A native parser success is modeled, not implemented. The real module
        # still constructs/frees its private native-layout policy object.
        return self.parser_error

    def _load_isids(self):
        self.events.append(("load_isids", self.argument(0), self.argument(1)))
        return self.isids_error

    def _open(self):
        self.events.append(("filp_open", self.cstring(self.argument(0)), self.argument(1)))
        return self.open_error if self.open_error else self.file

    def _read_file(self):
        file, buffer, count, position = (self.argument(i) for i in range(4))
        if file != self.file:
            raise AssertionError("unexpected mock file")
        offset = self.uint(position)
        data = self.file_data[offset:offset + count]
        self.write(buffer, data)
        self.put(position, offset + len(data))
        self.events.append(("kernel_read", offset, len(data)))
        return len(data)

    def _hook_wrap(self):
        function, nargs, before, after, context = (self.argument(i) for i in range(5))
        name = self.native_names[function]
        index = len(self.hook_attempts)
        record = {"function": function, "nargs": nargs, "before": before,
                  "after": after, "context": context}
        self.hook_attempts.append((name, record))
        self.events.append(("hook_wrap", name))
        if index == self.hook_failure:
            return -4093  # KernelPatch HOOK_NO_MEM, not Linux ENOMEM.
        self.hooks[name] = record
        return 0

    def _hook_remove(self):
        function, before, after, remove = (self.argument(i) for i in range(4))
        if remove:
            raise AssertionError("module requested unsafe trampoline destruction")
        name = self.native_names[function]
        record = self.hooks.pop(name)
        if (before, after) != (record["before"], record["after"]):
            raise AssertionError("rollback removed the wrong callback")
        self.events.append(("hook_remove", name))
        return 0

    def _copy_to_user(self):
        destination, source, size = (self.argument(i) for i in range(3))
        copied = size - int(self.copy_short)
        self.write(destination, self.read(source, copied))
        return copied

    def gate_entries(self):
        return [record[key] for _, record in self.hook_attempts
                for key in ("before", "after") if record[key]]

    def _sleep(self):
        self.events.append(("msleep", self.argument(0)))
        if not self.complete_during_sleep:
            raise AssertionError("unexpected wait: no modeled callback can finish")
        for entry in self.gate_entries():
            state = self.uint(entry + GATE_STATE)
            if not state & CLOSED:
                raise AssertionError("drain waited before closing its gateway")
            self.put(entry + GATE_STATE, state & CLOSED)
        return 0

    def _permission(self):
        self.events.append(("permission",) + tuple(self.argument(i) for i in range(5)))
        return self.permission_error

    def _context_to_sid(self):
        state, text, length, output = (self.argument(i) for i in range(4))
        data = self.read(text, length).rstrip(b"\0")
        self.context_calls.append((state, data))
        if b"hidden" in data:
            return -22
        sid = 202 if data == b"target" else 101
        self.put(output, sid + (1000 if state == self.live_state else 0), 4)
        return 0

    def _sid_to_context(self):
        state, sid, output, length = (self.argument(i) for i in range(4))
        self.events.append(("sid_to_context", state, sid))
        result = self.allocate(len(self.canonical), "kmalloc", self.canonical)
        self.put(output, result)
        self.put(length, len(self.canonical), 4)
        return 0

    def _compute_av(self):
        state, ssid, tsid, tclass, output = (self.argument(i) for i in range(5))
        self.events.append(("compute_av", state, ssid, tsid, tclass))
        self.write(output, struct.pack("<5I", 5, 1, 10, 987, 2))
        return 0

    def _unexpected_original(self):
        raise AssertionError("test unexpectedly executed a native hook target")

    def initialize(self, arguments="policy=/clean/policy"):
        return self.call("rsk_init", self.string(arguments), self.string("test"), 0)

    def control(self, command="status", capacity=512):
        output = self.allocate(max(capacity, 1))
        result = self.call("rsk_control", self.string(command), output, capacity)
        return result, self.cstring(output) if result == 0 else ""

    def exit(self):
        return self.call("rsk_exit", 0)

    def arguments(self, *values, skip=0, result=0):
        address = self.allocate(120)
        self.put(address + FA_SKIP, skip, 4)
        self.put(address + FA_RET, result)
        for index, value in enumerate(values):
            self.put(address + FA_ARG0 + index * 8, value)
        return address

    def invoke(self, hook, arguments, after=False):
        entry = self.hooks[hook]["after" if after else "before"]
        return self.call(entry, arguments, 0)

    def native_live_allocations(self):
        return {address: item["kind"] for address, item in self.allocations.items()
                if item["kind"] in ("vmalloc", "vmalloc_user", "module_alloc", "kmalloc")
                and not item["freed"]}


class ProductionModule(unittest.TestCase):
    def assert_failed_before_hooks(self, machine, arguments, error):
        self.assertEqual(machine.initialize(arguments), error)
        self.assertEqual(machine.hook_attempts, [])
        # The real KP loader calls exit even if init already rolled back.
        self.assertEqual(machine.exit(), 0)
        self.assertEqual(machine.exit(), 0)
        self.assertNotIn("synchronize_rcu", machine.names())
        self.assertEqual(machine.native_live_allocations(), {})

    def test_missing_required_native_symbol_prevents_all_hooks(self):
        machine = ModuleMachine(missing=("policydb_read",))
        self.assert_failed_before_hooks(machine, "policy=/clean/policy", -2)
        self.assertNotIn("filp_open", machine.names())
        self.assertTrue(any("missing symbol policydb_read" in line for line in machine.logs))

    def test_native_credential_layout_mismatch_is_rejected(self):
        machine = ModuleMachine()
        machine.put(machine.kp_symbols["task_struct_offset"] + 10, 2040, 2)
        self.assert_failed_before_hooks(machine, "policy=/clean/policy", -93)

    def test_late_capture_and_early_file_mode_are_rejected(self):
        self.assert_failed_before_hooks(ModuleMachine(), "capture", -11)
        self.assert_failed_before_hooks(ModuleMachine(initialized=False),
                                        "policy=/clean/policy", -11)

    def test_invalid_arguments_and_live_policy_dump_are_rejected(self):
        for arguments in ("policy=relative", "unknown", "policy=/sys/fs/selinux/policy"):
            with self.subTest(arguments=arguments):
                self.assert_failed_before_hooks(ModuleMachine(), arguments, -22)

    def test_file_open_type_size_and_parser_failures_are_clean(self):
        cases = ("open", "directory", "empty", "oversized", "parser", "initial_sids")
        for case in cases:
            with self.subTest(case=case):
                machine = ModuleMachine(parser_error=-22 if case == "parser" else 0,
                                        isids_error=-12 if case == "initial_sids" else 0)
                error = -22
                if case == "open":
                    machine.open_error, error = -2, -2
                elif case == "directory":
                    machine.put(machine.inode + ABI["inode_mode"], 0o040755, 2)
                elif case in ("empty", "oversized"):
                    machine.put(machine.inode + ABI["inode_size"],
                                0 if case == "empty" else 32 * 1024 * 1024 + 1)
                    error = -27
                elif case == "initial_sids":
                    error = -12
                self.assert_failed_before_hooks(machine, "policy=/clean/policy", error)
                self.assertEqual(machine.names().count("filp_close"), int(case != "open"))
                if case == "parser":
                    self.assertNotIn("policydb_destroy", machine.names())
                if case == "initial_sids":
                    self.assertEqual(machine.names().count("policydb_destroy"), 1)
                    self.assertNotIn("sidtab_destroy", machine.names())

    def test_page_and_gateway_allocation_failures_release_private_policy(self):
        for operation, error in (("vmalloc_user", -12), ("vmalloc_to_page", -14),
                                 ("module_alloc", -12)):
            with self.subTest(operation=operation):
                machine = ModuleMachine(allocation_failure=operation)
                self.assert_failed_before_hooks(machine, "policy=/clean/policy", error)
                self.assertEqual(machine.names().count("policydb_destroy"), 1)

    def test_missing_hook_frees_the_never_published_gateway_page(self):
        machine = ModuleMachine(missing=("selinux_setprocattr",))
        self.assert_failed_before_hooks(machine, "policy=/clean/policy", -2)
        self.assertTrue(any(event[:1] == ("vfree",) and event[2] == "module_alloc"
                            for event in machine.events))

    def test_each_hook_install_failure_rolls_back_idempotently(self):
        for failed_index in range(4):
            with self.subTest(failed_index=failed_index):
                machine = ModuleMachine(hook_failure=failed_index)
                self.assertEqual(machine.initialize(), -4093)
                self.assertEqual(machine.hooks, {})
                removed = [event[1] for event in machine.events if event[0] == "hook_remove"]
                self.assertEqual(removed, list(reversed(QUERY_HOOKS[:failed_index])))
                for entry in machine.gate_entries():
                    self.assertEqual(machine.uint(entry + GATE_STATE), CLOSED)
                    self.assertEqual(machine.uint(entry + GATE_STATE + 8), 0)
                    self.assertEqual(machine.uint(entry + GATE_STATE + 16), 0)
                self.assertEqual(machine.exit(), 0)
                self.assertEqual(machine.exit(), 0)
                self.assertNotIn("synchronize_rcu", machine.names())
                self.assertEqual(list(machine.native_live_allocations().values()), ["module_alloc"])

    def test_successful_file_mode_controls_and_failed_output_are_atomic(self):
        machine = ModuleMachine()
        self.assertEqual(machine.initialize(), 0)
        self.assertEqual(tuple(machine.hooks), QUERY_HOOKS)
        result, message = machine.control()
        self.assertEqual(result, 0)
        self.assertIn("state=on source=file", message)
        self.assertIn(f"bytes={len(machine.file_data)} error=0 hooks=4", message)
        self.assertIn(f"target={FIXTURE_RELEASE} config={FIXTURE_CONFIG}", message)
        self.assertEqual(machine.control("off")[0], 0)
        self.assertEqual(machine.global_value("requested_enabled"), 0)
        self.assertIn("state=off", machine.control()[1])
        self.assertEqual(machine.control("on")[0], 0)
        self.assertEqual(machine.control("off", capacity=1)[0], -28)
        self.assertEqual(machine.global_value("requested_enabled"), 1)
        machine.copy_short = True
        self.assertEqual(machine.control("off")[0], -14)
        self.assertEqual(machine.global_value("requested_enabled"), 1)
        machine.copy_short = False
        self.assertEqual(machine.control("unknown")[0], -22)
        self.assertEqual(machine.exit(), 0)

    def test_exit_synchronizes_then_closes_drains_removes_and_frees(self):
        machine = ModuleMachine()
        self.assertEqual(machine.initialize(), 0)
        entry = machine.hooks[QUERY_HOOKS[0]]["before"]
        # Model a callback admitted before exit. The separate exact-instruction
        # gateway suite validates its admission/release race implementation.
        machine.put(entry + GATE_STATE, 1)
        machine.complete_during_sleep = True
        mark = len(machine.events)
        self.assertEqual(machine.exit(), 0)
        names = [event[0] for event in machine.events[mark:]]
        self.assertEqual(names.count("synchronize_rcu"), 1)
        self.assertLess(names.index("synchronize_rcu"), names.index("kp_gate_close_all"))
        self.assertLess(names.index("kp_gate_close_all"), names.index("kp_gate_drain"))
        self.assertLess(names.index("msleep"), names.index("hook_remove"))
        self.assertLess(names.index("hook_remove"), names.index("rsk_policy_destroy"))
        self.assertLess(names.index("rsk_policy_destroy"), names.index("vfree"))
        self.assertEqual(machine.global_value("baseline"), 0)
        self.assertEqual(machine.global_value("requested_enabled"), 0)
        self.assertEqual(machine.hooks, {})
        self.assertEqual(list(machine.native_live_allocations().values()), ["module_alloc"])
        self.assertEqual(machine.exit(), 0)
        self.assertEqual(machine.names().count("synchronize_rcu"), 1)

    def test_context_and_access_gateways_use_private_policy_and_live_permissions(self):
        machine = ModuleMachine()
        self.assertEqual(machine.initialize(), 0)
        baseline = machine.global_value("baseline")
        buffer = machine.allocate(PAGE, data=b"input\0")
        args = machine.arguments(0, buffer, 5)
        machine.invoke("sel_write_context", args)
        self.assertEqual(machine.uint(args + FA_SKIP, 4), 1)
        self.assertEqual(machine.uint(args + FA_RET), len(machine.canonical))
        self.assertEqual(machine.read(buffer, len(machine.canonical)), machine.canonical)
        self.assertEqual(machine.context_calls, [(baseline, b"input"), (machine.live_state, b"input")])
        permissions = [event for event in machine.events if event[0] == "permission"]
        self.assertEqual(permissions[-1][1:3], (machine.live_state, 33))
        self.assertIn(("sid_to_context", baseline, 101), machine.events)

        text = b"source target 7"
        machine.write(buffer, text + b"\0")
        args = machine.arguments(0, buffer, len(text))
        machine.invoke("sel_write_access", args)
        expected = b"5 ffffffff 1 a 1 2"
        self.assertEqual(machine.uint(args + FA_SKIP, 4), 1)
        self.assertEqual(machine.uint(args + FA_RET), len(expected))
        self.assertEqual(machine.read(buffer, len(expected)), expected)
        self.assertIn(("compute_av", baseline, 101, 202, 7), machine.events)
        self.assertEqual(machine.control()[0], 0)
        self.assertIn("context=1 access=1", machine.control()[1])
        self.assertEqual(machine.exit(), 0)

    def test_denials_stop_live_sid_registration(self):
        machine = ModuleMachine()
        self.assertEqual(machine.initialize(), 0)
        buffer = machine.allocate(PAGE, data=b"hidden\0")
        args = machine.arguments(0, buffer, 6)
        machine.invoke("sel_write_context", args)
        self.assertEqual(signed(machine.uint(args + FA_RET)), -22)
        self.assertEqual(machine.context_calls, [(machine.global_value("baseline"), b"hidden")])
        machine.permission_error = -13
        machine.context_calls.clear()
        args = machine.arguments(0, buffer, 6)
        machine.invoke("sel_write_context", args)
        self.assertEqual(signed(machine.uint(args + FA_RET)), -13)
        self.assertEqual(machine.context_calls, [])
        self.assertEqual(machine.exit(), 0)

    def test_current_gate_prechecks_then_leaves_native_transition_in_control(self):
        machine = ModuleMachine()
        self.assertEqual(machine.initialize(), 0)
        text = b"valid\n"
        buffer = machine.allocate(PAGE, data=text + b"\0")
        args = machine.arguments(machine.string("current"), buffer, len(text), result=77)
        machine.invoke("selinux_setprocattr", args)
        self.assertEqual(machine.uint(args + FA_SKIP, 4), 0)
        self.assertEqual(machine.uint(args + FA_RET), 77)
        self.assertEqual(machine.uint(args + FA_ARG0 + 16), len(text) - 1)
        self.assertEqual(machine.read(buffer, len(text)), b"valid\0")
        self.assertEqual(machine.context_calls, [(machine.global_value("baseline"), b"valid")])
        machine.write(buffer, b"hidden\0")
        args = machine.arguments(machine.string("current"), buffer, 6)
        machine.invoke("selinux_setprocattr", args)
        self.assertEqual(machine.uint(args + FA_SKIP, 4), 1)
        self.assertEqual(signed(machine.uint(args + FA_RET)), -22)
        self.assertEqual(machine.exit(), 0)

    def test_system_off_and_previously_handled_queries_fall_through(self):
        machine = ModuleMachine()
        self.assertEqual(machine.initialize(), 0)
        buffer = machine.allocate(PAGE, data=b"valid\0")
        for case in ("system", "off", "previous_handler"):
            with self.subTest(case=case):
                machine.set_uid(9999 if case == "system" else 10000)
                self.assertEqual(machine.control("off" if case == "off" else "on")[0], 0)
                skip = int(case == "previous_handler")
                args = machine.arguments(0, buffer, 5, skip=skip, result=77)
                machine.invoke("sel_write_context", args)
                self.assertEqual(machine.uint(args + FA_SKIP, 4), skip)
                self.assertEqual(machine.uint(args + FA_RET), 77)
        self.assertEqual(machine.context_calls, [])
        self.assertEqual(machine.exit(), 0)

    def test_published_status_and_stale_gate_survive_module_memory_release(self):
        machine = ModuleMachine()
        self.assertEqual(machine.initialize(), 0)
        args = machine.arguments(machine.live_state)
        entry = machine.hooks["selinux_kernel_status_page"]["before"]
        machine.invoke("selinux_kernel_status_page", args)
        self.assertEqual(machine.uint(args + FA_SKIP, 4), 1)
        self.assertEqual(machine.uint(args + FA_RET), machine.global_value("status_page"))
        status_memory = machine.global_value("status_memory")
        self.assertEqual(struct.unpack("<5I", machine.read(status_memory, 20)), (1, 0, 1, 0, 1))
        self.assertEqual(machine.exit(), 0)
        self.assertEqual(set(machine.native_live_allocations().values()), {"module_alloc", "vmalloc_user"})
        self.assertEqual(machine.read(status_memory, 20), struct.pack("<5I", 1, 0, 1, 0, 1))
        machine.uc.mem_unmap(machine.MODULE_BASE, machine.module_bytes)
        stale_args = machine.arguments(machine.live_state, result=77)
        machine.call(entry, stale_args, 0)
        self.assertEqual(machine.uint(stale_args + FA_SKIP, 4), 0)
        self.assertEqual(machine.uint(stale_args + FA_RET), 77)

    def test_initial_capture_retries_a_failed_native_load_then_publishes_input(self):
        machine = ModuleMachine(initialized=False)
        self.assertEqual(machine.initialize("capture"), 0)
        self.assertEqual(tuple(machine.hooks), QUERY_HOOKS + ("security_load_policy",))
        self.assertIn("state=armed source=initial-input", machine.control()[1])
        self.assertEqual(machine.control("on")[0], -11)
        data = b"INITIAL INPUT POLICY: MOCK PARSER"
        blob = machine.allocate(len(data), data=data)
        args = machine.arguments(machine.live_state, blob, len(data))
        machine.invoke("security_load_policy", args)
        self.assertEqual(machine.global_value("snapshot_stage"), 1)
        machine.put(args + FA_RET, -22)
        machine.invoke("security_load_policy", args, after=True)
        self.assertEqual(machine.global_value("snapshot_stage"), 0)
        self.assertEqual(machine.global_value("baseline"), 0)
        machine.invoke("security_load_policy", args)
        machine.put(args + FA_RET, 0)
        machine.put(machine.live_state + ABI["state_initialized"], 1, 1)
        machine.invoke("security_load_policy", args, after=True)
        self.assertEqual(machine.global_value("snapshot_stage"), 2)
        self.assertNotEqual(machine.global_value("baseline"), 0)
        self.assertEqual(machine.global_value("baseline_bytes"), len(data))
        parsed = [event[2] for event in machine.events if event[0] == "policydb_read"]
        self.assertEqual(parsed, [data])
        self.assertIn("state=on source=initial-input", machine.control()[1])
        self.assertEqual(machine.exit(), 0)


if __name__ == "__main__":
    unittest.main(argv=[__file__] + unittest_args)
