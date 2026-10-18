/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * AArch64 callback gateway. All branches and the state ADR resolve within this
 * template. It has no external references and can be copied to executable
 * memory without applying relocations. x0 is the KernelPatch argument object;
 * upstream x1 is ignored because hook_chain_remove can clear it concurrently.
 *
 * CLOSED and the active count share one atomic word. A call acquires a count
 * before it loads either module pointer. It releases the count only AFTER the
 * module callback returns here. An old, delayed dispatcher can therefore enter
 * a closed, retained gateway without touching any freed module memory.
 */
#ifndef __ASSEMBLY__
#define __ASSEMBLY__
#endif
#include "gateway.h"

    .section .rodata.kp_gate, "a", %progbits
    .p2align 6
    .global kp_gate_template_start
    .global kp_gate_template_end
    .type kp_gate_template_start, %object
kp_gate_template_start:
    /* BTI C is an architectural NOP on the target ARMv8.0 hardware. */
    .inst 0xd503245f
    adr x16, .Lstate
.Lenter:
    ldaxr x9, [x16]
    tbnz x9, #63, .Lclosed
    add x10, x9, #1
    stlxr w11, x10, [x16]
    cbnz w11, .Lenter

    stp x29, x30, [sp, #-32]!
    mov x29, sp
    str x16, [sp, #16]
    ldr x17, [x16, #8]
    ldr x1, [x16, #16]
    cbz x17, .Lreturned
    blr x17
.Lreturned:
    ldr x16, [sp, #16]
.Lleave:
    ldaxr x9, [x16]
    sub x10, x9, #1
    stlxr w11, x10, [x16]
    cbnz w11, .Lleave
    ldp x29, x30, [sp], #32
    ret
.Lclosed:
    clrex
    ret

    .if (. - kp_gate_template_start) > KP_GATE_STATE_OFFSET
    .error "gateway instructions overlap their state"
    .endif
    .org kp_gate_template_start + KP_GATE_STATE_OFFSET
.Lstate:
    .quad 0  /* CLOSED flag | active calls */
    .quad 0  /* module handler */
    .quad 0  /* module context */
    .org kp_gate_template_start + KP_GATE_STRIDE
kp_gate_template_end:
    .size kp_gate_template_start, . - kp_gate_template_start

    .section .note.GNU-stack, "", %progbits
