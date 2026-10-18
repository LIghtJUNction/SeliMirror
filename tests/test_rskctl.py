#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Execute the built rskctl ELF in AArch64 emulation with every syscall mocked.

Dependencies are the project's test requirements: Unicorn and pyelftools.
Run: python3 tests/test_rskctl.py [--binary dist/rskctl]

The actual static executable and its libc execute from their ELF entry point.
Mocks check command packing, true userspace pointer arguments, libc errno
translation, input validation, and key wiping after authentication. No syscall
is forwarded to the host. A missing-KP result is simulated: this does not test
real KernelPatch authentication, kernel hooks, an Android device, or Hunter.
The syscall mock set covers the Zig 0.13 static musl build; a different libc
may require additional explicitly implemented mocks and otherwise fails.
"""

import argparse
import io
import struct
from pathlib import Path

from unicorn import Uc, UC_ARCH_ARM64, UC_MODE_ARM, UC_HOOK_INTR
from unicorn.arm64_const import UC_ARM64_REG_X0, UC_ARM64_REG_X1, UC_ARM64_REG_X2, UC_ARM64_REG_X3, UC_ARM64_REG_X4, UC_ARM64_REG_X5, UC_ARM64_REG_X8, UC_ARM64_REG_SP
from elftools.elf.elffile import ELFFile

registers = [UC_ARM64_REG_X0, UC_ARM64_REG_X1, UC_ARM64_REG_X2, UC_ARM64_REG_X3, UC_ARM64_REG_X4, UC_ARM64_REG_X5]


def run(elf, label, arguments, key=b'emulator-test-key\n', mode='ok', expected=0, key_fd=3):
    segments = [x for x in elf.iter_segments() if x['p_type'] == 'PT_LOAD']
    uc = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
    begin = min(s['p_vaddr'] & -4096 for s in segments)
    end = max((s['p_vaddr'] + s['p_memsz'] + 4095) & -4096 for s in segments)
    uc.mem_map(begin, end - begin)
    for segment in segments:
        uc.mem_write(segment['p_vaddr'], segment.data())
    stack = 0x70000000
    uc.mem_map(stack - 0x200000, 0x200000)
    cursor = stack - 0x1000

    def push(data):
        nonlocal cursor
        cursor -= len(data)
        uc.mem_write(cursor, data)
        return cursor

    args = ['rskctl', *arguments]
    pointers = [push(a.encode() + b'\0') for a in args]
    random = push(bytes(range(16)))
    phdr = next((s['p_vaddr'] for s in elf.iter_segments()
                 if s['p_type'] == 'PT_PHDR'), begin + elf['e_phoff'])
    aux = [3, phdr, 4, elf['e_phentsize'], 5, elf['e_phnum'],
           6, 4096, 7, 0, 9, elf['e_entry'], 11, 0, 12, 0, 13, 0, 14, 0,
           23, 0, 25, random, 31, pointers[0], 0, 0]
    words = [len(args), *pointers, 0, 0, *aux]
    cursor = (cursor - len(words) * 8) & -16
    uc.mem_write(cursor, struct.pack('<' + 'Q' * len(words), *words))
    uc.reg_write(UC_ARM64_REG_SP, cursor)
    calls = []
    output = bytearray()
    key_position = 0
    exit_code = None
    key_address = None
    heap = 0x50000000

    def cstring(address):
        value = bytearray()
        while True:
            c = uc.mem_read(address + len(value), 1)[0]
            if not c:
                return bytes(value)
            value.append(c)
            assert len(value) <= 4096

    def syscall(uc, interrupt, _):
        nonlocal key_position, exit_code, heap, key_address
        assert interrupt == 2, (label, interrupt)
        number = uc.reg_read(UC_ARM64_REG_X8)
        a = [uc.reg_read(r) for r in registers]
        result = 0
        if number in (93, 94):
            exit_code = a[0]
            if key_address is not None:
                assert uc.mem_read(key_address, 64) == bytes(64), 'key not wiped'
            uc.emu_stop()
            return
        if number == 45:
            key_address = a[0]
            command = a[1] & 0xffff
            calls.append(command)
            assert a[1] == (0x80000d0911580000 | command), 'unsafe or wrong packing'
            assert cstring(a[0]) == key.split(b'\n')[0], 'wrong user key pointer'
            if mode == 'absent':
                result = -22
            elif command == 0x1000:
                result = 0x11581158
            elif command == 0x1008:
                result = 0xd08 if mode == 'version' else 0xd09
            elif command == 0x1022:
                assert cstring(a[2]) == b'selimirror'
                assert cstring(a[3]) in (b'status', b'on', b'off')
                assert a[5] == 4096
                assert stack - 0x200000 <= a[4] < stack
                if mode == 'fault':
                    result = -14
                else:
                    uc.mem_write(a[4], b'state=on source=mock\n\0')
            elif command == 0x1020:
                assert cstring(a[2]) == b'/data/local/tmp/module.kpm'
                assert cstring(a[3]) in (b'capture', b'policy=/data/local/tmp/policy')
                assert a[4] == 0
            elif command == 0x1021:
                assert cstring(a[2]) == b'selimirror'
                assert a[3] == 0
            else:
                raise AssertionError(('unexpected KP command', command))
        elif number == 63:
            assert a[0] == key_fd, ('unexpected fd read', a[0])
            chunk = key[key_position:key_position + a[2]]
            if chunk:
                uc.mem_write(a[1], chunk)
            key_position += len(chunk)
            result = len(chunk)
        elif number == 64:
            assert a[0] in (1, 2)
            output.extend(uc.mem_read(a[1], a[2]))
            result = a[2]
        elif number == 66:
            assert a[0] in (1, 2)
            for index in range(a[2]):
                address, length = struct.unpack('<QQ', uc.mem_read(a[1] + 16 * index, 16))
                output.extend(uc.mem_read(address, length))
                result += length
        elif number == 29:
            result = 0 if mode == 'tty' and a[0] == key_fd else -25
        elif number == 96:
            result = 99
        elif number in (99, 134, 135, 226, 215):
            result = 0
        elif number == 222:
            size = (a[1] + 4095) & -4096
            uc.mem_map(heap, size)
            result = heap
            heap += size
        else:
            raise AssertionError((label, 'unmocked Linux syscall', number, a))
        uc.reg_write(UC_ARM64_REG_X0, result & ((1 << 64) - 1))

    uc.hook_add(UC_HOOK_INTR, syscall)
    uc.emu_start(elf['e_entry'], 0, count=1000000)
    assert exit_code == expected, (label, exit_code, output.decode(errors='replace'))
    assert b'emulator-test-key' not in output
    if mode == 'absent':
        assert calls == [0x1000]
        assert b'errno 22' in output
    elif mode == 'version':
        assert calls == [0x1000, 0x1008]
    elif mode == 'fault':
        assert calls == [0x1000, 0x1008, 0x1022]
        assert b'errno 14' in output
    elif expected == 0 and arguments[-1] != '--help':
        assert calls[:2] == [0x1000, 0x1008] and len(calls) == 3
    else:
        assert calls == []
    print('PASS:', label)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', type=Path,
                        default=Path(__file__).resolve().parents[1] / 'dist/rskctl',
                        help='Built static AArch64 userspace helper (default: project/dist/rskctl).')
    options = parser.parse_args()
    binary = options.binary.read_bytes()
    elf = ELFFile(io.BytesIO(binary))
    if (elf.elfclass != 64 or not elf.little_endian or
            elf['e_machine'] != 'EM_AARCH64' or elf['e_type'] != 'ET_EXEC'):
        parser.error('requires a static little-endian AArch64 ET_EXEC binary')
    if any(s['p_type'] in ('PT_INTERP', 'PT_DYNAMIC') for s in elf.iter_segments()):
        parser.error('dynamic executables are not supported by this mock runtime')
    run(elf, 'help skips authentication', ['--help'])
    for action in ('status', 'on', 'off', 'unload'):
        run(elf, action, ['--key-fd', '3', action])
    run(elf, 'default stdin', ['status'], key_fd=0)
    run(elf, 'load capture', ['--key-fd', '3', 'load', '/data/local/tmp/module.kpm', 'capture'])
    run(elf, 'load file', ['--key-fd', '3', 'load', '/data/local/tmp/module.kpm', 'policy=/data/local/tmp/policy'])
    run(elf, 'safe missing KP fallback', ['--key-fd', '3', 'status'], mode='absent', expected=1)
    run(elf, 'version mismatch prevents command', ['--key-fd', '3', 'on'], mode='version', expected=1)
    run(elf, 'libc errno EFAULT propagation', ['--key-fd', '3', 'status'], mode='fault', expected=1)
    run(elf, 'overlong key refused', ['--key-fd', '3', 'status'], key=b'a'*64+b'\n', expected=1)
    run(elf, 'NUL key refused', ['--key-fd', '3', 'status'], key=b'abc\0def\n', expected=1)
    run(elf, 'empty key refused', ['--key-fd', '3', 'status'], key=b'\n', expected=1)
    run(elf, 'TTY key refused', ['--key-fd', '3', 'status'], mode='tty', expected=1)
    run(elf, 'invalid fd refused', ['--key-fd', '-1', 'status'], expected=2)
    print('16 actual-ELF userspace scenarios passed; all syscalls were mocked.')


if __name__ == '__main__':
    main()
