# SeliMirror

Android KernelPatch module research for examining SELinux policy visibility and compatibility.

## Status

**Development repository — no installable release is currently published.**

This repository currently contains project information and CI scaffolding only. It does **not** provide an installable KPM or KernelSU ZIP. Source code or binaries that evade SELinux or third-party security checks are not included.

## Scope

- Android ARM64 / Linux 4.14 compatibility research
- Build reproducibility and module packaging checks
- Safe lifecycle testing and regression tests
- Explicit compatibility information for supported kernels

Target kernel reference: [Laulan56/android_kernel_xiaomi_sm8150 (miui)](https://github.com/Laulan56/android_kernel_xiaomi_sm8150/tree/miui)

Related upstream projects: [KernelPatch](https://github.com/bmax121/KernelPatch), [ReSukiSU](https://github.com/ReSukiSU/ReSukiSU), and [Kam](https://github.com/MemDeco-WG/Kam).

## Version policy

When a compatible module is ready for release, each release must use a unique Git tag, a strictly increasing `versionCode`, and published checksums. A KernelSU module ZIP also needs a valid root-level `module.prop` and the required files for its actual installation method.

KPM binaries are not interchangeable with KernelSU flashable ZIP packages. Compatibility and load paths must be documented separately.

## Releases

There is no published version yet. See [Releases](https://github.com/LIghtJUNction/SeliMirror/releases) for future verified builds.

## Security

Do not use kernel modules from an unverified source on a daily-use device. Test changes on a recovery-capable device and keep a backup of your boot image.
