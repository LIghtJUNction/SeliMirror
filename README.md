# SeliMirror

将 ReSukiSU 的“阻止 SELinux 检测”查询逻辑移植为独立 KernelPatch 模块，适配所指定的 Xiaomi SM8150 `miui` 内核源码。当前版本为 **`0.1.0`**。项目代码名为 **SeliMirror**。

模块使用独立的基准 SELinux 策略处理应用查询，保留真实策略的权限检查和进程上下文转换约束。交付包含完整源码、构建脚本、主机测试、中文说明，以及一个参考配置下编译的 `.kpm`。

**KernelSU Modules 发行包特别提醒：** `module/` 是一个用于 KernelSU 安装的 *KPM 伴随包*，只存放参考 `.kpm` 和 `rskctl`。它不会自动修改 SELinux、安装 KernelPatch、捕获原始策略或替你加载内核模块。KPM 的 `capture` 需要早期内核加载，常规 KernelSU 安装时机太晚；完整说明见下方加载章节。不要把能在 KernelSU Manager 中安装理解为已经生效。

**尚未连接真实设备，也未运行 Hunter 6.72。** 编译和仿真结果见 [验证记录](docs/validation-report.md)。附带二进制使用下述参考配置，设备使用前应按实际运行内核的配置重新构建。为统一项目名称，这次将先前经过 ELF 审计的 ARM64 参考构建仅更改内嵌名称、版本及诊断字符串（保留原始布局及指令），**并未重新使用内核头文件编译新版本**。文档中的真机与完整重新构建验证仍须执行。

发布前检查发现参考 KPM 的 9 条诊断字符串在改名时被 NUL 填充截断，现已在各自原有字符串空间内恢复完整日志，并同步 `module/FILES.sha256`。修正没有改变指令、ELF 布局或重定位；已增加完整日志回归检查，详情见[验证记录](docs/validation-report.md)。

## 实现范围

| 接口 | 实际 hook | 模块启用后的应用路径 |
|---|---|---|
| `/sys/fs/selinux/context` | `sel_write_context` | 先检查真实 `CHECK_CONTEXT` 权限，再用基准策略验证并返回规范化上下文 |
| `/sys/fs/selinux/access` | `sel_write_access` | 先检查真实 `COMPUTE_AV` 权限，再按基准策略计算完整访问决定，序号固定为 `1` |
| `/proc/.../attr/current` 的写入 | `selinux_setprocattr` | 只预检 `current`，基准策略接受后交回原生函数处理真实 SID、凭据及转换限制 |
| `/sys/fs/selinux/status` 的 read/mmap | `selinux_kernel_status_page` | 原生 open 获得基准状态页，继续使用内核原生 read/mmap 行为 |

调用者筛选与所读上游一致：**原始真实 UID ≥ 10000**。不使用有效 UID，不对多用户 UID 取余，不增加 root 授权名单豁免。权限检查仍基于调用者的真实 SID。

私有策略和实时策略使用各自独立的 SID 表。私有 SID 仅用于查询，不会写入真实进程凭据。模块不重新加载全局策略，也不关闭真实 SELinux。完整顺序、边界条件及与上游的细微差异见 [行为说明](docs/semantics.md)。

## 适配条件

| 项目 | 本版本要求 |
|---|---|
| 内核源码 | `Laulan56/android_kernel_xiaomi_sm8150`，`miui` 分支固定提交 `bd65f57d4c36882a5dfd34557e64198516ed392b` |
| 内核版本 | 该提交的 Linux `4.14.268`，编译时使用真实生成的内核头文件 |
| KernelPatch | **固定提交 `ef52c62b339bd2da51880922249bf4edef71b1cf`，版本号 `0.13.9`** |
| 架构 | AArch64、小端、4 KiB 页 |
| 必需配置 | `ARM64`、`ARM64_4K_PAGES`、`SECURITY_SELINUX`、`KALLSYMS`、`KALLSYMS_ALL`、`MODULES` |
| 当前排除的配置 | CFI、LTO、结构体随机化、KASAN、Shadow Call Stack，以及会改变锁结构布局的调试配置；构建脚本会拒绝已列出的不支持选项 |

目标 4.14 树包含 state-aware SELinux、指针形式 SID 表及 queued rwlock 等回移代码。因此本项目直接使用该树生成的结构定义，不使用 KernelPatch SDK 中的 Linux 占位头文件。

加载时检查 KernelPatch 版本、完整内核 release 字符串、必需符号及 `task_struct`/`cred` 的关键偏移。**这些检查不能证明运行内核的所有配置或 KernelPatch 提交相同。** `kpver=0.13.9` 只是版本号，不能替代固定提交要求；不同提交的同版本 loader 也可能有不同退出行为。

必须使用与设备实际内核一致的源码、补丁和配置。不能通过删除 release 检查来适配任意“4.14”内核。源码记录和精确链接见 [UPSTREAM.md](UPSTREAM.md)。

## 构建

在 Linux 主机上准备 Bash、Git、Python 3.10 或更新版本、make、宿主 GCC、`bc`，以及 ARM64 编译工具链。已验证工具链为 **Zig 0.13.0 所带 Clang/LLD 18.1.6**。脚本不会安装系统软件。

一种隔离的工具链准备方式：

```sh
python3 -m venv .venv
. .venv/bin/activate
python3 -m pip install ziglang==0.13.0
RSK_ZIG="$(python3 -c 'import pathlib, ziglang; print(pathlib.Path(ziglang.__file__).with_name("zig"))')"
```

### 1. 获取固定版本源码

```sh
python3 tools/fetch-sources.py
```

默认获取目标内核及其必需的 exFAT 子模块，放入 `third_party/`。添加 `--references` 可一并获取 ReSukiSU/BakaSU、KernelPatch 和 Kam，便于核对实现。已有 checkout 版本不符或有本地修改时，脚本会拒绝改动，允许通过 `--destination` 选择另一个目录。

### 2. 准备实际内核配置

设备构建应提供该设备实际运行内核的完整配置：

```sh
tools/prepare-kernel.sh \
  --kernel third_party/android_kernel_xiaomi_sm8150 \
  --out third_party/kernel-out \
  --config /absolute/path/device.config \
  --zig "$RSK_ZIG"
```

脚本只在输出目录中规范化显式提供的配置副本，执行 `prepare0`，并生成原生 SELinux 头文件；不需要编译整个内核镜像。重用已有输出目录且不传配置选项时，脚本保留已有 `.config`，拒绝隐式改写。

复现本次参考构建可将上面的 `--config` 改为：

```text
--config configs/raphael-stock-reference.config
```

该参考配置来自树内 `raphael_stock_defconfig`，补入同树 `raphael_defconfig` 的 CPU mask：`LITTLE=15`、`BIG=112`、`PRIME=128`，再由 Kconfig 生成。**用户没有提供设备 `.config`，所以这个配置是可复现的编译参考，不代表已确认的设备配置。** 新输出目录不传配置时，准备脚本使用相同参考规则。

目标内核自身不支持源码或输出路径中包含空白、冒号；准备脚本会明确报错。配置文件路径和编译器路径可以包含空格。

### 3. 编译和检查 KPM

```sh
make build ZIG="$RSK_ZIG"
make check
```

主要产物：

- `dist/selimirror.kpm`：ARM64 ELF 可重定位 KPM。
- `dist/build-manifest.json`：内核提交、release、配置摘要、编译器版本、KPM 摘要及 ELF 审计结果。
- `build/commands.json`：本次构建的完整编译参数，按参数数组保存。

也可以使用单独的 Clang/LLD 或 ARM64 GCC/binutils：

```sh
make build KPM_CC=clang KPM_LD=ld.lld
```

本次交付实际验证的是 Zig/Clang 路径。自选工具链仍须通过最终 ELF 审计；不能生成动态链接、GOT/TLS 或 loader 不支持的重定位。

可选用户态管理工具：

```sh
python3 tools/build-rskctl.py --zig "$RSK_ZIG"
```

输出 `dist/rskctl`，为静态 ARM64 用户态程序。它通过 KernelPatch supercall 使用真正的用户态输出缓冲区调用模块控制接口，命令见下文。

## 提供基准策略

模块不会把 root 规则已经修改过的实时策略自动标记为原始策略。加载参数只接受以下两种模式，不支持运行时替换基准策略。

### 模式 A：捕获首次策略输入

参数为 `capture`，空参数也选择此模式。将 KPM 嵌入 KernelPatch 镜像，加载事件设为 **`pre-exec-init`**，使其在 Android 首次加载 SELinux 策略前安装观察 hook。

在固定版本 `kptools` 的既有补丁命令中追加以下 extra 参数：

```text
-M dist/selimirror.kpm -T kpm -N selimirror -V pre-exec-init -A capture
```

这些选项的含义来自固定版本的 [kptools](https://github.com/bmax121/KernelPatch/blob/ef52c62b339bd2da51880922249bf4edef71b1cf/tools/kptools.c)。项目没有生成或刷写设备 boot 镜像；首次设备测试应使用可恢复的测试镜像并保留原镜像。

在原生 `security_load_policy` 首次成功返回后，模块用其仍有效的二进制输入建立私有策略。首次原生加载失败时继续等待；私有解析失败时记为 `error` 并保持不生效。已完成首次策略加载再用 `capture` 动态加载，会返回 `-EAGAIN`，此时可使用文件模式。

`pre-kernel-init` 太早，此时 SELinux 状态尚未就绪。普通 `post-fs-data` 加载通常太晚，不能倒推出修改前策略。若其他组件在首次内核加载前已修改输入，捕获也无法证明输入干净。合法的后续策略重载或布尔值变化可能使此初始输入与 ReSukiSU 在添加 root 规则前保存的副本不同，详见 [行为说明](docs/semantics.md)。

### 模式 B：指定原始二进制策略

参数格式：

```text
policy=/absolute/path/clean-policy
```

适用于 SELinux 已初始化后的动态加载。文件应是**对应同一系统版本、root 规则修改前的可加载二进制策略**。`.cil`、文本规则和修改后的实时导出都不能替代它。

模块要求绝对路径、普通文件、非空、最大 32 MiB，使用 `O_NOFOLLOW` 拒绝最终路径组件为符号链接，并处理短读、截断和文件增长。明确拒绝字面路径 `/sys/fs/selinux/policy`。这些检查不能认证文件来源，也不能识别所有可解析但来自错误系统的策略；文件来源和系统匹配仍需由提供者确认。

## 加载、控制和卸载

以下命令在**已运行上述固定版本 KernelPatch 的目标设备、已授权的 root shell** 中执行。将对应配置构建的 `rskctl` 和 KPM 放到可执行、可读取的位置。

`rskctl` 从文件描述符读取 1–63 字节的 SuperKey，默认读取标准输入，以换行或 EOF 结束；拒绝终端直接输入、NUL 和 CR 字节，不会把密钥作为命令行参数。以下 `3</absolute/path/superkey-file` 表示调用者已有、受限访问的密钥文件；不要把密钥文件加入本仓库。

```sh
./rskctl --key-fd 3 load /data/local/tmp/selimirror.kpm \
  policy=/absolute/path/clean-policy 3</absolute/path/superkey-file

./rskctl --key-fd 3 status 3</absolute/path/superkey-file
./rskctl --key-fd 3 off    3</absolute/path/superkey-file
./rskctl --key-fd 3 on     3</absolute/path/superkey-file
./rskctl --key-fd 3 unload 3</absolute/path/superkey-file
```

支持正确使用 `sc_kpm_control` 的管理器也可调用同名模块的 `status`、`on`、`off`。控制输出缓冲区建议 512 字节以上。`on` 需要已有基准策略；没有基准时返回 `-EAGAIN`。过小缓冲区或用户复制失败不会改变开关。

这里提供专用工具，是因为固定版本 KernelPatch 的 `truncate ... module ctl0` 实现把内核栈缓冲区交给用户复制接口，在该 4.14 内核的正常用户地址限制下会失败；参见 [supercmd.c](https://github.com/bmax121/KernelPatch/blob/ef52c62b339bd2da51880922249bf4edef71b1cf/kernel/patch/common/supercmd.c)、[复制封装](https://github.com/bmax121/KernelPatch/blob/ef52c62b339bd2da51880922249bf4edef71b1cf/kernel/patch/common/utils.c) 和 [原生 seq_buf_to_user](https://github.com/Laulan56/android_kernel_xiaomi_sm8150/blob/bd65f57d4c36882a5dfd34557e64198516ed392b/lib/seq_buf.c)。`rskctl` 使用真正的用户态缓冲区。

该工具还为 supercall 命令设置最高位：固定提交的 KernelPatch 按低 16 位解码命令，而未接管的 ARM64 系统调用会把它视为负的 truncate 长度并拒绝。这样认证失败或 KP 缺失时不会尝试改变同名文件大小。它先检查 hello 和精确版本号，再发送模块命令；仍不支持任意 KernelPatch 版本。

所有管理操作应**串行执行**。固定版本 KernelPatch 的 `module_control0()` 会替换共享 `ctl_args`，本模块无法从回调内部保护 loader 的这个先行操作。普通应用查询可以并行；不要并发执行 load/control/unload，也不要同时让其他模块增删同一 hook 链。

`status` 返回的主要字段：

| 字段 | 含义 |
|---|---|
| `state=armed` | 已安装 hook，等待首次策略输入；当前不替换查询 |
| `state=on` / `off` | 基准策略已就绪，后续查询开关开启 / 关闭 |
| `state=error` | 首次输入的私有解析失败；查看 `error` 的负 errno |
| `source=initial-input` / `file` | 基准来自首次输入 / 指定文件 |
| `bytes`、`hooks` | 原始二进制策略大小、当前安装的 hook 数量 |
| `context/access/current/status` | 进入模块处理路径的累计次数；不等同于成功次数 |
| `target`、`config` | 构建时的完整内核 release、配置 SHA-256 |

关闭功能后，已经开始的查询可以完成；新的查询使用实时策略。**已打开的 status FD 或 mmap 保留打开时取得的页面。** 对比开启、关闭状态时，应结束测试进程并重新打开接口。

### 卸载时的内存处理

本模块提供退出路径。它先等待已有控制调用，再关闭常驻 ARM64 入口、等待已进入的回调返回、移除本模块回调并释放私有策略。没有使用返回 `-EBUSY` 来假设可以阻止 loader 卸载，也没有在 RCU 读侧控制回调中等待。

固定版本 KernelPatch 的 hook 链没有可依赖的回调释放宽限期，状态页的原生 FD 也没有本模块可接管的释放引用。因此采取以下保留策略：

- 已发布的入口代码页在模块退出后保持关闭，清除指向模块代码和数据的指针，并保留到重启，避免旧 dispatcher 地址指向已释放代码。
- 状态页一旦交给原生 open，就保留到重启，使旧 FD/mmap 可以继续读；从未发布的状态页会释放。
- 使用 `hook_unwrap_remove(..., 0)` 保留 KernelPatch 自身 hook 链内存，避免直接释放正在执行的 trampoline。

每次成功加载最多保留两个 4 KiB 页面，另有 KernelPatch 链自身的内存。已尝试发布 hook 后失败的加载也可能保留入口页。重复加载、卸载会累积这些页面；只是切换功能时应使用 `on` / `off`。完整设备并发验证仍是验收项目。

## 测试与验收

```sh
make test
python3 -m pip install -r tests/requirements.txt
make test-gateway
make test-module
make test-rskctl
```

`make test` 直接编译生产 `src/core.c`，启用 ASan/UBSan。若环境明确禁止 LeakSanitizer 读取 `/proc/*/task`，可使用 `ASAN_OPTIONS=detect_leaks=0 make test`；这只关闭泄漏检查，不能表述为完成了全部 sanitizer 检查。

ARM64 测试执行实际编译的入口代码或最终 KPM，替换内核外部函数。它验证模块控制流和生命周期，不模拟真实 SELinux 策略解析、真实 hook dispatcher 或手机 CPU 的内存序。`test-rskctl` 需要先编译用户态工具，执行实际静态 ELF，并模拟全部系统调用。当前结果及未执行项见 [验证记录](docs/validation-report.md)，设备测试步骤见 [验证计划](docs/validation-plan.md)。

Hunter 6.72 的目标验收需要在同一设备、系统和 APK 上对比模块关闭、ReSukiSU 开启、本 KPM 开启，并记录各个 SELinux 子项。单独 root shell 查询不会覆盖真实 UID ≥ 10000 的应用路径。

## 目录与许可

| 路径 | 内容 |
|---|---|
| `src/`、`include/` | KPM、原生策略封装、KernelPatch ABI 桥及 ARM64 入口 |
| `tools/` | 固定源码获取、原生头准备、编译、ELF 审计、可选用户态控制工具 |
| `tests/` | 核心逻辑、ARM64 入口及最终模块生命周期测试 |
| `configs/` | 本次构建的完整参考配置 |
| `docs/` | 行为、设计边界、验证记录和设备验收计划 |
| `dist/` | 本次构建产物和摘要；不默认纳入 Git 跟踪 |

仓库整体按 GPL-2.0 提供，具体文件保留自己的 SPDX 标记；KernelPatch 派生接口的 `GPL-2.0-or-later` 标记不变。参见 [LICENSE](LICENSE)、[NOTICE](NOTICE) 和 [UPSTREAM.md](UPSTREAM.md)。

本仓库通过 GitHub Actions 执行单元测试、最终 ELF 仿真与 KernelSU Modules ZIP 检查，`v*` 标签触发不可变发布；发布设置未启用时不能发布符合 KernelSU Modules 的 release。`third_party/`、`build/` 和工具链可通过脚本重建，不包含在 Git 中。

## KernelSU Modules 发行和版本

- 唯一模块 ID：`selimirror`，版本：`v0.1.0`，`versionCode=100`（以后每次发布必须递增）。
- `module.yaml` 用于官方目录展示，`module/module.prop` 是版本的唯一来源；安装 ZIP 根目录必须包含 `module.prop`。
- `python3 scripts/check_release.py` 可校验元数据、参考 ELF 和生成的 ZIP；`python3 scripts/check_release.py --zip dist/selimirror-100-v0.1.0.zip` 会检查整个包。
- `.github/workflows/ci.yml` 运行测试，`.github/workflows/release.yml` 在 `v*` tag 或手动触发后使用官方固定 SHA 的 `module-release` action 预检并发布一个 ZIP。
- 发布前仓库所有者需要在 **Settings → General → Releases → Enable release immutability** 开启不可变发布。GitHub 仅对开启后发布的版本赋予不可变属性。
- 完成首次发布后，若希望上架，还必须安装 KernelSU Modules GitHub App 并通过 https://developers.kernelsu.org/ 提交审核；不能把 GitHub Release 等同于已上架。

请勿在 ZIP 中加入私钥、SuperKey、原始设备策略或用户数据。
