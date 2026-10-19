# KernelPatch 0.13.3 compatibility status

Status: **investigation recorded; no compatibility update merged or released**.

## Reported failure

The SeliMirror v0.1.0 embedded KPM returned `-93` during
`pre-exec-init` with `capture`:

```text
KP load_module: [selimirror] failed with [capture] error: -93
KP load kpm: selimirror, event: pre-exec-init, rc: -93
```

The existing reference code expects KernelPatch 0.13.9. A runtime
version mismatch is consistent with this error; the error alone does
not establish that every other compatibility check passes.

## Target to evaluate

- KernelPatch source commit: `043c0c3bae68ddc6f2894b4e483d8f54cb85d112`.
- Upstream `version` at this commit: `0.13.3`.
- Target Android kernel reference: `Laulan56/android_kernel_xiaomi_sm8150`,
  `miui` branch (Linux 4.14.268 reference).

## Merge and validation status

A local experimental v0.1.1 compatibility package exists, but it is
**not committed to this branch**, and it is **not a released build**.
It was prepared from an earlier binary baseline. In the meantime,
commit `0f6982c39d22828d97b4268f36c3a6e7557e183d` fixed truncated
diagnostic strings in the distributed v0.1.0 reference KPM. Replacing
that file with the local older binary would discard these fixes.

Any eventual compatibility update must preserve current diagnostics,
use consistent source and binary versions, and pass the repository's
tests and device checks. No real device load success or Hunter 6.72
result has been established for KernelPatch 0.13.3.

This file records compatibility information only; it does not change
or enable module behavior.
