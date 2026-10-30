<div align="center">
  <h1>SeliMirror</h1>
  <p><strong>把 ReSukiSU 的 SELinux 查询镜像逻辑移植为独立 KernelPatch KPM。</strong></p>
  <p>Xiaomi SM8150 · Linux 4.14.268 · KernelPatch 0.13.9 · AArch64</p>

  [![Release](https://img.shields.io/github/v/release/LIghtJUNction/SeliMirror?style=flat-square)](https://github.com/LIghtJUNction/SeliMirror/releases/latest)
  [![Target](https://img.shields.io/badge/target-Xiaomi%20SM8150%204.14.268-111111?style=flat-square)](UPSTREAM.md)
  [![Status](https://img.shields.io/badge/status-experimental-111111?style=flat-square)](docs/validation-report.md)
  [![License](https://img.shields.io/github/license/LIghtJUNction/SeliMirror?style=flat-square)](LICENSE)

  [机制](#它实际做什么) · [兼容条件](#严格兼容条件) · [构建](#构建) · [加载](#提供基准策略) · [验证](docs/validation-report.md)
</div>

> [!CAUTION]
> `module/` 和 Release ZIP 只是 **KernelSU 可安装的 KPM 伴随包**：它们会放置参考 `.kpm` 与 `rskctl`，但不会安装 KernelPatch、捕获干净策略、修改 SELinux，或自动把 KPM 加载进内核。能在 KernelSU Manager 中安装，**不代表 SeliMirror 已生效**。

> [!WARNING]
> 当前版本尚未连接真实设备，也未运行 Hunter 6.72。附带 KPM 是参考构建，并非针对你的启动内核重新编译。生产设备必须使用精确匹配的内核源码、补丁提交和实际 `.config` 重建。

## 它实际做什么

Android 应用查询 SELinux 时，正常路径直接读取实时策略。SeliMirror 在保留真实权限检查的前提下，允许部分查询改用一份独立的基准策略：

```text
应用发起 SELinux 查询
          ↓
先按真实策略检查调用者权限
          ↓
允许后，用独立基准策略回答指定查询
          ↓
真实进程 SID、凭据和全局 SELinux 保持原生管理
```

它不是关闭 SELinux，也不重新加载全局策略。私有策略与实时策略使用独立 SID 表；私有 SID 只用于查询，不写入真实进程凭据。

## Hook 范围

| 用户可见接口 | Hook | 启用后的行为 |
| --- | --- | --- |
| `/sys/fs/selinux/context` | `sel_write_context` | 先检查真实 `CHECK_CONTEXT`，再用基准策略验证并规范化上下文 |
| `/sys/fs/selinux/access` | `sel_write_access` | 先检查真实 `COMPUTE_AV`，再按基准策略计算完整访问决定 |
| `/proc/.../attr/current` 写入 | `selinux_setprocattr` | 只预检 `current`；基准策略接受后仍交给原生函数处理真实 SID、凭据和转换约束 |
| `/sys/fs/selinux/status` read/mmap | `selinux_kernel_status_page` | 通过原生 open 获得基准状态页，继续使用内核原生 read/mmap 行为 |

调用者筛选与固定上游一致：原始真实 UID `>= 10000`。它不使用有效 UID、不对多用户 UID 取余，也不添加 root 白名单绕过。

完整顺序、重载差异和边界见 [语义说明](docs/semantics.md)。

## 严格兼容条件

| 项目 | 固定要求 |
| --- | --- |
| 内核源码 | `Laulan56/android_kernel_xiaomi_sm8150`，`miui` 分支提交 `bd65f57d4c36882a5dfd34557e64198516ed392b` |
| Linux release | `4.14.268`，并使用该树真实生成的内核头文件 |
| KernelPatch | 提交 `ef52c62b339bd2da51880922249bf4edef71b1cf`，版本 `0.13.9` |
| 架构 | AArch64、小端、4 KiB 页 |
| 必需配置 | `ARM64`、`ARM64_4K_PAGES`、`SECURITY_SELINUX`、`KALLSYMS`、`KALLSYMS_ALL`、`MODULES` |
| 当前排除 | CFI、LTO、结构体随机化、KASAN、Shadow Call Stack 及会改变锁布局的调试配置 |

```text
“Linux 4.14”         不够
“KernelPatch 0.13.9” 不够
release 字符串相同     也不够
```

版本号不能标识同版本下的具体提交，release 字符串也不能证明结构布局、补丁和配置完全相同。删除检查去“兼容更多内核”会把可检测的不匹配变成内核内存破坏风险。

固定来源、链接与补丁身份见 [UPSTREAM.md](UPSTREAM.md)。

## 构建

主机需要 Linux、Bash、Git、Python 3.10+、make、GCC、`bc` 和 ARM64 工具链。已验证工具链是 Zig 0.13.0 所带 Clang/LLD 18.1.6。

### 1. 准备隔离工具链

```bash
python3 -m venv .venv
. .venv/bin/activate
python3 -m pip install ziglang==0.13.0
RSK_ZIG="$(python3 -c 'import pathlib, ziglang; print(pathlib.Path(ziglang.__file__).with_name("zig"))')"
```

### 2. 获取固定源码

```bash
python3 tools/fetch-sources.py
```

默认只获取目标内核及必需 exFAT 子模块到 `third_party/`。`--references` 额外获取 ReSukiSU/BakaSU、KernelPatch 与 Kam 供审阅。已有 checkout 版本不符或有本地修改时，脚本会停止，不会覆盖。

### 3. 使用设备实际配置准备头文件

```bash
tools/prepare-kernel.sh \
  --kernel third_party/android_kernel_xiaomi_sm8150 \
  --out third_party/kernel-out \
  --config /absolute/path/device.config \
  --zig "$RSK_ZIG"
```

参考配置可用：

```text
--config configs/raphael-stock-reference.config
```

该文件只用于可重复编译，来自树内 defconfig 合成，**不是任何用户设备实际 `.config` 的证明**。

### 4. 构建与审计

```bash
make build ZIG="$RSK_ZIG"
make check
```

主要产物：

| 产物 | 作用 |
| --- | --- |
| `dist/selimirror.kpm` | ARM64 ELF 可重定位 KPM |
| `dist/build-manifest.json` | 内核提交、release、配置摘要、编译器、哈希和 ELF 审计 |
| `build/commands.json` | 完整编译参数数组 |

可选构建控制器：

```bash
python3 tools/build-rskctl.py --zig "$RSK_ZIG"
```

自选 Clang/LLD 或 GCC/binutils 仍必须通过最终 ELF 审计；不能产生动态链接、GOT/TLS 或 loader 不支持的重定位。

## 提供基准策略

模块需要一份“查询镜像”的基准二进制策略。它不把已经被 root 规则修改的实时策略自动当成原始策略。

### 模式 A：早期捕获首次策略输入

将 KPM 嵌入 KernelPatch 镜像，并在 `pre-exec-init` 加载：

```text
-M dist/selimirror.kpm -T kpm -N selimirror -V pre-exec-init -A capture
```

模块会观察首次成功的原生 `security_load_policy` 输入并建立私有策略。普通 KernelSU `post-fs-data` 已经太晚；动态加载 `capture` 通常返回 `-EAGAIN`。

即使是早期捕获，也只能证明“捕获到首次进入该 hook 的输入”，不能证明其他更早组件没有修改它。

### 模式 B：显式干净策略文件

```text
policy=/absolute/path/clean-policy
```

文件必须是同一系统版本、root 规则修改前的可加载二进制策略。`.cil`、文本规则和修改后的 `/sys/fs/selinux/policy` 都不能替代。

模块要求绝对路径、普通非空文件、最大 32 MiB，并拒绝最终路径组件为符号链接。它能检查文件形态，不能认证文件来源或系统匹配；来源仍由操作者负责。

## 控制

在已运行固定 KernelPatch 的目标设备、已授权 root shell 中，使用为同一环境构建的 `rskctl`：

```bash
./rskctl --key-fd 3 load /data/local/tmp/selimirror.kpm \
  policy=/absolute/path/clean-policy \
  3</absolute/path/superkey-file

./rskctl --key-fd 3 status 3</absolute/path/superkey-file
./rskctl --key-fd 3 off    3</absolute/path/superkey-file
./rskctl --key-fd 3 on     3</absolute/path/superkey-file
./rskctl --key-fd 3 unload 3</absolute/path/superkey-file
```

`rskctl` 从文件描述符读取 1–63 字节 SuperKey，拒绝终端直接输入、NUL 与 CR，不把密钥放进命令行参数。不要把密钥文件加入仓库。

`on` 只有在基准策略存在时才能成功。禁用、卸载和控制缓冲区失败必须保持可预测状态；具体返回值见 [语义说明](docs/semantics.md)。

## KernelSU 伴随包

Release 中的 ZIP：

- 安装参考 KPM 与 `rskctl`；
- 提供校验和与元数据；
- 不补丁 boot；
- 不安装 KernelPatch；
- 不捕获策略；
- 不自动调用 KPM loader；
- 不保证与你的运行内核兼容。

`capture` 必须在首次 SELinux 策略加载前挂钩，因此常规 KernelSU 模块安装时机无法替代内核镜像级早期加载。

## 当前验证状态

已经完成的证据包括源码、构建脚本、主机测试、ARM64 仿真、ELF/重定位审计、清单与校验和检查。参考 KPM 改名时曾出现 9 条日志字符串被 NUL 截断，现已在原字符串空间内恢复，并加入回归检查；指令、ELF 布局和重定位未改变。

尚未完成：

- 真实手机加载；
- Hunter 6.72 兼容；
- 与设备实际 `.config` 的完整重编译；
- 目标查询在真实 Android 进程中的行为；
- 失败恢复、休眠、重启与长期稳定性。

不要把“host test 通过”“ELF 可加载格式通过”或“ZIP 可安装”写成真机兼容结论。完整证据见 [验证记录](docs/validation-report.md)。

## 来源与许可

SeliMirror 移植自 ReSukiSU/BakaSU 的相应查询逻辑，并固定引用 KernelPatch 与 Xiaomi SM8150 内核来源。所有来源、提交、补丁和许可说明见 [UPSTREAM.md](UPSTREAM.md) 与 [LICENSE](LICENSE)。
