# 本次开发验证记录

日期：2026-10-18。模块版本：`0.1.0`。

**已完成源码移植、ARM64 交叉编译、最终 ELF 审计、核心逻辑测试和基于正式 KPM 的 ARM64 仿真。没有连接真实 Android 设备，没有运行 Hunter 6.72。**

## 产物与构建配置

| 项目 | 本次结果 |
|---|---|
| KPM | `dist/selimirror.kpm` |
| 文件大小 | 35,328 字节 |
| 格式 | ELF64、小端、AArch64、`ET_REL` |
| 编译器 | Zig 0.13.0 所带 Clang 18.1.6 |
| 链接器 | LLD 18.1.6，使用 `-r` |
| 目标内核提交 | `bd65f57d4c36882a5dfd34557e64198516ed392b` |
| 参考 release | `4.14.268-perf-gbd65f57d4c36` |
| 参考配置 | `configs/raphael-stock-reference.config` |
| `.config` SHA-256 | `f2feadf62787fa1b7acccce254e3bb25348e61c8025266a0ed1b41a58d3e1bd9` |
| `autoconf.h` SHA-256 | `3aa74313c6c1fce3b2498822961708bb0f0127f1eed09f491212f6f396a76111` |
| KPM SHA-256 | `76e0cdf5fb7d955615f9ab3ef15915177d5235e9a2a7f67dee181a580c4ed625` |

可机器读取的记录在 [build-manifest.json](../dist/build-manifest.json)。重新构建后的摘要以新生成的清单为准。

该配置由目标源码内 `raphael_stock_defconfig` 生成，并显式使用同树 `raphael_defconfig` 的 CPU mask `15 / 112 / 128` 修正旧参考配置的空值。用户没有提供实际运行设备的完整配置；本次不能确认附带二进制与具体设备 ABI 一致。

## 已执行检查

| 检查 | 结果 | 实际范围 |
|---|---|---|
| 原生头文件准备 | 通过 | 使用目标树 `prepare0` 和原生 SELinux 头生成器 |
| ARM64 编译与链接 | 通过 | 全部七个 KPM 源文件；C 代码启用 `-Wall -Wextra -Werror` |
| 最终 ELF 审计 | 通过 | KPM 元信息、入口段、导入、重定位及不允许的用户态链接段 |
| 核心逻辑 | **501 项断言通过** | 直接编译 `src/core.c`，使用 ASan 和 UBSan |
| 常驻 ARM64 入口 | **13 项测试通过** | Unicorn 执行实际 `build/gateway_asm.o` 指令 |
| 正式 KPM 生命周期 | **16 项测试通过** | 对最终 `.kpm` 重定位并执行正式 init/control/exit 和查询回调 |
| 用户态控制工具 | **16 个场景通过** | 执行实际静态 `rskctl` ELF 与 libc，全部系统调用由测试替身处理 |
| 源码脚本 | 通过 | 固定提交检查、配置复用、从空目录准备、错误配置拒绝、参数边界 |

ASan/UBSan 测试使用 `ASAN_OPTIONS=detect_leaks=0`，原因是本环境不允许 LeakSanitizer 读取其需要的 `/proc/*/task` 信息。因此没有宣称 LeakSanitizer 通过；地址和未定义行为检查保持启用。

### ELF 结果

最终导入恰好六个 KernelPatch 符号：

```text
compat_copy_to_user
hook_unwrap_remove
hook_wrap
kallsyms_lookup_name
kpver
symbol_lookup_name
```

其中 `kallsyms_lookup_name` 是 KernelPatch 导出的函数指针变量。本模块通过别名区分它与原生内核同名函数，其他原生调用均通过有类型的动态解析指针完成。没有把内核函数留成 loader 无法解析的外部导入。

共 757 个 RELA 重定位，类型为 `257, 275, 277, 278, 282, 283, 285, 286`，都属于固定 loader 支持的类型。`.kpm.init`、`.kpm.ctl0`、`.kpm.exit` 各保存一个函数指针。保留的非分配 `.llvm_addrsig` 是地址显著性表，不是 LLVM bitcode；审计不会把它误判成 LTO。

### 核心逻辑覆盖

生产代码测试覆盖目标内核的 access 解析规则、16 位类号转换、超长数值、`0xA0` 空白、嵌入 NUL、无额外可读尾字节的输入、两个 4087 字节边界用例、输出容量及 NUL 长度规则。

通过记录实际策略操作回调顺序，验证真实权限优先、私有与实时 SID 分离、基准拒绝后不登记实时 SID、普通查询忽略实时转换错误、access 源已登记而目标失败时的副作用，以及 current 属性筛选和换行处理。UID 测试使用原始真实 UID 边界，包括多用户数值。

### ARM64 常驻入口覆盖

13 项测试执行实际编译指令，检查入口副本使用自己的状态、上下文不依赖上游 `udata`、参数及栈保留、关闭标志、活动计数、独占存储失败重试，以及回调返回到常驻代码之后才减少计数。

关闭、等待和指针擦除后，测试解除模拟模块处理函数的内存映射，再通过旧入口地址调用，确认不会访问已释放的函数或数据。竞争写入在测试中通过受控指令步骤模拟；不是手机多核硬件内存序的证明。

### 正式 KPM 生命周期覆盖

`tests/elf_machine.py` 只接受本项目实际使用的 ARM64 重定位，未知导入或重定位会使测试失败。`tests/test_module.py` 从正式 ELF 读取入口段，执行模块内部代码，只有外部 KernelPatch 与内核函数由测试替身提供。

测试涵盖：

1. 必需符号或 hook 目标缺失、task/cred 偏移不匹配时拒绝加载。
2. 太晚的 capture、太早的文件模式、非法参数及实时 policy 字面路径被拒绝。
3. 文件打开失败、目录、空文件、过大文件、模拟解析失败和初始 SID 载入失败后的清理。
4. status 分配、页转换、入口分配失败，以及每一个文件模式 hook 注册失败时的逆序回滚。
5. 模块自行回滚后，loader 再次调用 exit 不重复释放。
6. 文件模式成功后 `status` / `on` / `off` 的控制逻辑；输出容量不足或用户复制失败不改变状态。
7. 成功退出时先原生 RCU 同步，再关闭入口、等待已入场回调、以 `remove=0` 移除回调，最后销毁私有策略。
8. context/access/current/status 的正式回调经过常驻入口执行，权限使用实时状态，查询使用私有状态。
9. 已发布状态页被保留；正式 KPM 映射解除后，旧入口调用仍然安全返回。
10. 首次原生策略加载失败后允许重试，成功时解析原始 hook 参数输入并发布基准。

这些测试的 `policydb_read`、`policydb_load_isids`、权限服务、RCU 和实际 patch 操作均是明确标注的替身。测试没有执行完整 Linux SELinux parser，也没有加载真实 KPM 到内核。

### 用户态管理工具

`dist/rskctl` 是 28,392 字节的静态 ELF64 AArch64 `ET_EXEC`，没有动态解释器。SHA-256 为 `d6d68232b821142686cdfeb6e82f20f420979d5e69615b9d3b98bd3ec06bba63`，构建信息见 [rskctl-build-manifest.json](../dist/rskctl-build-manifest.json)。使用同一 Zig 工具链编译；在 x86_64 上直接编译源码会被架构检查拒绝，避免套用错误的系统调用号。

`tests/test_rskctl.py` 使用 Unicorn 执行实际静态 ELF 和 libc，实现受控 Linux/KP 系统调用替身。16 个场景覆盖 help、status/on/off/unload、两种 load 参数、默认 stdin、错误 FD、终端输入拒绝、空密钥、过长密钥、嵌入 NUL、KP 缺失、版本不匹配及 libc `errno=14` 的错误传播。检查 supercall 的六个参数、4096 字节用户态输出缓冲区、所有命令的最高位，以及正常退出和认证后的失败退出均擦除密钥缓冲区。

该客户端为固定 KP 协议设置命令最高位；固定版本 KP 只取命令低 16 位。目标内核原生 truncate 的负长度检查位于路径查找前，因此未接管或认证失败的调用不会调整文件大小。源码注释记录对应上游函数位置。客户端没有向开发主机发出 KernelPatch 系统调用，仿真没有验证真实设备认证、文件读取权限或 Android 运行环境。

## 原生结构测量

以下数值由目标树、上述完整配置和原生头文件的 `sizeof` / `offsetof` 编译探针取得，不来自 KernelPatch 占位结构：

| 结构 / 字段 | 字节数 / 字节偏移 |
|---|---:|
| `sizeof(struct selinux_state)` | 32 |
| `sizeof(struct selinux_ss)` | 576 |
| `sizeof(struct policydb)` | 496 |
| `sizeof(struct sidtab)` | 7176 |
| `sizeof(struct context)` | 80 |
| `sizeof(rwlock_t)` | 8 |
| `sizeof(spinlock_t)` | 4 |
| `sizeof(struct mutex)` | 32 |
| `selinux_state.initialized` | 3 |
| `selinux_state.ss` | 24 |
| `selinux_ss.policydb` | 8 |
| `selinux_ss.policy_rwlock` | 504 |
| `selinux_ss.latest_granting` | 512 |
| `selinux_ss.status_page` | 536 |
| `selinux_ss.status_lock` | 544 |
| `task_struct.cred` | 2048 |
| `cred.uid` | 4 |
| `cred.security` | 120 |
| `file.f_inode` | 32 |
| `file.private_data` | 200 |
| `inode.i_mode` | 0 |
| `inode.i_size` | 80 |

正式模块通过真实结构定义访问成员；这些常数只用于仿真外部对象的测试夹具。集成测试检查嵌入的配置摘要，遇到不同配置会失败，要求重新测量，不能直接把夹具套用于另一配置。

## 开发脚本验证

`fetch-sources.py` 已对真实干净 checkout 验证内核、exFAT、KernelPatch、BakaSU、Kam 的五个固定提交，并确认错误 HEAD 会被拒绝且原 checkout 不变。原始公开源码下载已完成；这次脚本测试复用了本地 checkout，没有再次下载整棵内核。

`prepare-kernel.sh` 已完成以下检查：

- 从空输出目录准备，生成的 `.config` 和 `autoconf.h` 摘要与本次构建一致。
- 复用已有 `.config`，逐字节保留配置。
- 删除 `SIDTAB_HASH_BITS` 制造过期配置后，拒绝静默更新并保留输入。
- 显式配置路径和编译器路径包含空格时准备成功。
- Shell 语法、`--help`、必需参数与源码路径验证。

本版本提供的构建命令见 [README](../README.md)，可使用附带参考配置重现同一配置摘要。

## 已知行为差异和验收边界

- capture 的基准时刻是首次传入内核的策略输入；上游是在添加 root 规则前复制其当时的策略。中间若有合法重载或布尔值修改，二者可能不同。
- 文件模式可以解析策略，但不能证明策略来源正确或与系统匹配。
- 内存不足时，本实现和上游的分配次数、SID 登记副作用不完全一致。
- current 交回原生实现时再次检查 `SETCURRENT`，可能增加一条允许审计或在实时策略并发变化时返回不同结果。
- 关闭和卸载不会改变已经打开的 status FD/mmap 所持页面；要比较新行为需重新打开。
- 常驻关闭入口及已发布状态页保留至重启；重复加载会积累少量页面及 KernelPatch 链内存。
- loader 的控制参数与 hook 链管理需要外部串行；仿真不能验证其他模块同时修改链的情况。

具体源码依据及条件见 [行为说明](semantics.md) 和 [UPSTREAM.md](../UPSTREAM.md)。

## 未执行的项目

| 项目 | 状态 |
|---|---|
| 用户实际内核完整配置与运行 ABI 的比对 | 未获得设备配置 |
| 目标 KernelPatch loader 中的真实 KPM 加载 | 未执行 |
| 同系统原始策略的真实内核解析和全量 AV 决定对照 | 未执行 |
| 真机 read/mmap/mprotect 及多核卸载压力测试 | 未执行 |
| 启动时 `pre-exec-init` 捕获的实际时序 | 未执行 |
| Hunter 6.72 SELinux 各子项 | 未执行 |

这些项目的验收步骤在 [validation-plan.md](validation-plan.md)。因此，本次交付可以称为“已实现并通过所列主机验证的开发版本”，不能称为“已验证完全通过 Hunter 6.72”。
