SeliMirror v0.1.0 -- KernelPatch companion package

This is a KernelSU-installable packaging wrapper, not a universal SELinux
hiding module. Installing the ZIP ONLY stages bin/selimirror.kpm and bin/rskctl.
It does not install KernelPatch, alter a boot image, add hooks or load the KPM.

The prebuilt ELF uses a reference config from the exact pinned Xiaomi SM8150
4.14.268 source, KernelPatch 0.13.9, and is NOT verified on a real device.
The target kernel and its configuration must match; rebuild from source if not.

For capture mode, embed the KPM in a KP-patched test boot image and request
pre-exec-init before the initial SELinux policy load. For late dynamic loading,
provide a verified policy=/absolute/path/clean-policy and a valid KP SuperKey
via rskctl's --key-fd; do not put secrets in the module or Git repository.
Do not install this on other kernels and expect it to work.

See https://github.com/LIghtJUNction/SeliMirror for full docs and limitations.
