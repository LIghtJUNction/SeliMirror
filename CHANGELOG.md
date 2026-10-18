# SeliMirror v0.1.0

Initial experimental release.

- Port four ReSukiSU/BakaSU SELinux query surfaces to a KernelPatch KPM.
- Add early snapshot and explicit clean-policy file modes, plus an ARM64 controller.
- Pin the Xiaomi SM8150 4.14.268 and KernelPatch 0.13.9 source revisions.
- Add a KernelSU-installable **companion ZIP** with `versionCode=100`; it stages
  the KPM but **cannot load it or obtain a clean policy automatically**.
- Add source, ABI audits, host/ARM64 emulator tests and reproducible build scripts.

**Not tested on an actual phone. Hunter 6.72 compatibility is unverified.**
The bundled reference binary was rebranded from the audited `0.1.0-dev`
output without a new kernel recompilation. For a production device, rebuild
against its exact boot kernel, patches, and config before use.
