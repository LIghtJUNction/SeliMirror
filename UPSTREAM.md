# 上游版本、来源与许可证

本仓库是面向指定 Xiaomi MIUI 4.14 内核的独立 KernelPatch KPM 移植项目。项目名称用于说明行为来源，不表示获得 ReSukiSU/BakaSU、KernelPatch、Xiaomi 内核维护者或 Kam 作者的官方背书。

## 固定版本

所有实现依据固定到以下提交。构建与复核应使用这些完整 SHA，避免分支后续变化改变 ABI 或行为；源码获取入口见 [tools/fetch-sources.py](tools/fetch-sources.py)。

| 项目 | 固定提交 | 本项目用途 |
|---|---|---|
| [Baka-SU/BakaSU](https://github.com/Baka-SU/BakaSU)（原 ReSukiSU） | [`896e8981e0ed76ec14d1dcb39ab793438b304886`](https://github.com/Baka-SU/BakaSU/tree/896e8981e0ed76ec14d1dcb39ab793438b304886) | SELinux hide 四接口、策略备份、UID 和错误语义的来源。 |
| [Laulan56/android_kernel_xiaomi_sm8150](https://github.com/Laulan56/android_kernel_xiaomi_sm8150)，`miui` | [`bd65f57d4c36882a5dfd34557e64198516ed392b`](https://github.com/Laulan56/android_kernel_xiaomi_sm8150/tree/bd65f57d4c36882a5dfd34557e64198516ed392b) | 真实内核头文件、SELinux 状态结构与查询服务、selinuxfs 事务、构建适配依据。 |
| [bmax121/KernelPatch](https://github.com/bmax121/KernelPatch) | [`ef52c62b339bd2da51880922249bf4edef71b1cf`](https://github.com/bmax121/KernelPatch/tree/ef52c62b339bd2da51880922249bf4edef71b1cf) | 原生 KPM 元数据与入口、hook ABI、符号命名空间及运行时结构偏移。 |
| [MemDeco-WG/Kam](https://github.com/MemDeco-WG/Kam) | [`3835842ca90cefc621383e72e01078481122aa30`](https://github.com/MemDeco-WG/Kam/tree/3835842ca90cefc621383e72e01078481122aa30) | 按用户要求阅读 README，参考模块工具与构建、真机工作流的定位。 |

用户提供的 `https://github.com/ReSukiSU/ReSukiSU` 在研究时重定向到 `Baka-SU/BakaSU`。固定提交的 [README 第 1–8 行](https://github.com/Baka-SU/BakaSU/blob/896e8981e0ed76ec14d1dcb39ab793438b304886/docs/README.md#L1-L8) 也记录了原名 ReSukiSU。本仓库对外名称为 SeliMirror，文档保留 ReSukiSU 的原名及代码来源，全部不可变源码链接使用其新仓库名和固定 SHA。

## ReSukiSU/BakaSU 的代码来源

行为移植主要依据以下内核文件，具体一致之处与有意保留的差异见 [docs/semantics.md](docs/semantics.md)：

| 上游位置 | 参考内容 |
|---|---|
| [kernel/feature/selinux_hide.c，240–395 行](https://github.com/Baka-SU/BakaSU/blob/896e8981e0ed76ec14d1dcb39ab793438b304886/kernel/feature/selinux_hide.c#L240-L395) | context/access 的真实 UID 条件、权限检查、备份策略查询及响应格式。 |
| [同文件，449–578 行](https://github.com/Baka-SU/BakaSU/blob/896e8981e0ed76ec14d1dcb39ab793438b304886/kernel/feature/selinux_hide.c#L449-L578) | current 上下文转换与 status 页面选择。 |
| [同文件，1017–1059 行](https://github.com/Baka-SU/BakaSU/blob/896e8981e0ed76ec14d1dcb39ab793438b304886/kernel/feature/selinux_hide.c#L1017-L1059) | 状态页的早期快照和晚加载规范化。 |
| [同文件，1219–1300 行](https://github.com/Baka-SU/BakaSU/blob/896e8981e0ed76ec14d1dcb39ab793438b304886/kernel/feature/selinux_hide.c#L1219-L1300) | 备份/真实双 SID 表及错误路径的副作用。 |
| [kernel/selinux/rules.c，185–244 行](https://github.com/Baka-SU/BakaSU/blob/896e8981e0ed76ec14d1dcb39ab793438b304886/kernel/selinux/rules.c#L185-L244) | 在添加 root 规则前备份策略和初始化独立 SID 表。 |
| [kernel/selinux/sepolicy.c，1142–1221 行](https://github.com/Baka-SU/BakaSU/blob/896e8981e0ed76ec14d1dcb39ab793438b304886/kernel/selinux/sepolicy.c#L1142-L1221) | 通过策略二进制读写复制 policydb 的实现背景。 |

上游 [README 许可证段落](https://github.com/Baka-SU/BakaSU/blob/896e8981e0ed76ec14d1dcb39ab793438b304886/docs/README.md#L54-L58) 明确区分：`kernel/` 为 **GPL-2.0-only**，其他未单列部分为 **GPL-3.0-or-later**，图形资源另有许可安排。此移植依据的是 `kernel/` 代码及其 [kernel/LICENSE](https://github.com/Baka-SU/BakaSU/blob/896e8981e0ed76ec14d1dcb39ab793438b304886/kernel/LICENSE#L1-L7)，没有把上游根目录 GPLv3 当作内核移植许可证。没有纳入管理器 UI、图标、其他美术资源或用户态 daemon。

上游该功能文件没有独立的作者版权标题；其历史与贡献归属保留在原仓库。项目还明确列出 KernelSU 为上游、SukiSU-Ultra 为分叉来源，见 [Credit](https://github.com/Baka-SU/BakaSU/blob/896e8981e0ed76ec14d1dcb39ab793438b304886/docs/README.md#L68-L72)。本仓库不将这些已有工作署名为本次移植者原创。

## 目标 Linux 内核

目标内核的 [COPYING 第 2–23 行](https://github.com/Laulan56/android_kernel_xiaomi_sm8150/blob/bd65f57d4c36882a5dfd34557e64198516ed392b/COPYING#L2-L23) 指明 GPLv2，并说明内核代码的版权属于其实际作者，许可证文本的 Free Software Foundation 署名不等于内核源码的作者署名。

本模块通过目标头文件使用结构与 ABI，并在运行时调用该内核的 SELinux 实现，没有把完整 SELinux 引擎复制进 KPM。上游 `services.c` 记录 Stephen Smalley、James Morris 等作者与贡献者，并列出 NEC、Hewlett-Packard、Trusted Computer Solutions、Tresys、Red Hat 等版权声明；`selinuxfs.c` 另有对应版权与 GPLv2 声明。见 [services.c 头部](https://github.com/Laulan56/android_kernel_xiaomi_sm8150/blob/bd65f57d4c36882a5dfd34557e64198516ed392b/security/selinux/ss/services.c#L1-L41) 和 [selinuxfs.c 头部](https://github.com/Laulan56/android_kernel_xiaomi_sm8150/blob/bd65f57d4c36882a5dfd34557e64198516ed392b/security/selinux/selinuxfs.c#L1-L15)。外部源码获取后保留原文件及其许可声明。

## KernelPatch ABI 的直接改编

`include/kp_api.h` 的元数据宏、入口类型、hook 参数布局及导入声明根据下列源码改编，文件保留 **Copyright (C) 2023 bmax121** 归属与 `GPL-2.0-or-later` SPDX 标记：

- [kernel/include/kpmodule.h，1–48 行](https://github.com/bmax121/KernelPatch/blob/ef52c62b339bd2da51880922249bf4edef71b1cf/kernel/include/kpmodule.h#L1-L48)：KPM 元数据与入口段。
- [kernel/include/hook.h，1–194 行](https://github.com/bmax121/KernelPatch/blob/ef52c62b339bd2da51880922249bf4edef71b1cf/kernel/include/hook.h#L1-L194)：hook 错误值及参数对象布局。
- [kernel/base/start.c，38–75 行](https://github.com/bmax121/KernelPatch/blob/ef52c62b339bd2da51880922249bf4edef71b1cf/kernel/base/start.c#L38-L75)：`kallsyms_lookup_name`、`printk` 是指针变量导出，以及内核/KP 版本导出。
- [kernel/base/symbol.c，1–54 行](https://github.com/bmax121/KernelPatch/blob/ef52c62b339bd2da51880922249bf4edef71b1cf/kernel/base/symbol.c#L1-L54)：KernelPatch 自身的符号查找入口。

`include/kp_offsets.h` 的偏移结构按 [kernel/linux/include/linux/cred.h，38–74 行](https://github.com/bmax121/KernelPatch/blob/ef52c62b339bd2da51880922249bf4edef71b1cf/kernel/linux/include/linux/cred.h#L38-L74) 和 [sched.h，43–64 行](https://github.com/bmax121/KernelPatch/blob/ef52c62b339bd2da51880922249bf4edef71b1cf/kernel/linux/include/linux/sched.h#L43-L64) 改编。文件记录 KernelPatch 来源及版本；没有把其占位 Linux 头文件混入目标内核的 include 路径。

命令行辅助程序 `tools/rskctl.c` 的调用常量和命令布局改编自 [user/supercall.h，1–76 行](https://github.com/bmax121/KernelPatch/blob/ef52c62b339bd2da51880922249bf4edef71b1cf/user/supercall.h#L1-L76) 与 [kernel/patch/include/uapi/scdefs.h，1–43 行](https://github.com/bmax121/KernelPatch/blob/ef52c62b339bd2da51880922249bf4edef71b1cf/kernel/patch/include/uapi/scdefs.h#L1-L43)，保留其 bmax121 版权归属和 GPL-2.0-or-later 标记；参数校验、密钥文件描述符读取与本模块命令行流程为本次实现。

KernelPatch 的 [README 许可证段落](https://github.com/bmax121/KernelPatch/blob/ef52c62b339bd2da51880922249bf4edef71b1cf/README.md#L43-L45) 标明 GPL 2.0；上述明确带 SPDX 的接口文件标为 GPL-2.0-or-later，改编文件继续保留该逐文件标记。本项目的 GPLv2 交付不改写上游文件的原始许可。

## 本次新增实现

| 本仓库文件 | 来源与处理 |
|---|---|
| `src/core.c`、`src/main.c` 及相关项目头文件 | 按 ReSukiSU 内核行为重写纯逻辑、KernelPatch 接入和基线获取；采用 GPL-2.0-only。没有复制上游管理器功能开关基础设施。 |
| `src/policy.c`、`src/kernel_api.c`、`src/memory.c` | 为固定目标内核编写私有策略状态、符号适配和必要运行库接口；采用 GPL-2.0-only。 |
| `include/kp_api.h`、`include/kp_offsets.h` | KernelPatch 接口的直接改编；保留上述来源、归属及 GPL-2.0-or-later。 |
| `tools/rskctl.c` | 使用 KernelPatch UAPI 命令布局编写本模块的管理客户端；保留上述来源、归属及 GPL-2.0-or-later。 |
| `src/gateway.c`、`src/gateway.S`、`include/gateway.h` | 本次编写的常驻入口与退出排空实现，文件采用 GPL-2.0-or-later；实现依据包括已审阅的 KernelPatch 调度和移除语义。 |
| `tests/test_core.c` | 本次编写，直接测试生产核心逻辑；GPL-2.0-only。 |

整体交付采用 GPLv2，具体文件的 SPDX 标记和已有归属随源码保留。完整 GPLv2 文本见 [LICENSE](LICENSE)。行为差异、构建范围和未完成的真机验收不是由许可证段落替代，分别见 [行为说明](docs/semantics.md) 与 [验证计划](docs/validation-plan.md)。

## Kam README 的阅读范围与本次使用

已阅读固定版本的英文 `README.md` 和中文 `README.zh-CN.md`，包括支持目标、模板、构建打包、adb/dev/MCP 联调、Agent Skills 入口及许可证说明。其 [英文简介与支持目标](https://github.com/MemDeco-WG/Kam/blob/3835842ca90cefc621383e72e01078481122aa30/README.md#L7-L39) 将 Kam 定位为 Android root 模块项目工具；[模板表](https://github.com/MemDeco-WG/Kam/blob/3835842ca90cefc621383e72e01078481122aa30/README.md#L114-L123) 区分标准用户态模块、元数据工作流和 AnyKernel3 内核 ZIP。中文 README 也说明标准模板生成 Magisk 风格 ZIP，并把 kamfw 定义为 Shell 模块框架。[中文说明](https://github.com/MemDeco-WG/Kam/blob/3835842ca90cefc621383e72e01078481122aa30/README.zh-CN.md#L13-L31)

本交付由 KernelPatch 直接加载原生 `.kpm`，构建使用目标内核头文件和 KPM ABI。该路径无需额外 Kam 用户态包装或 kamfw 运行时，因此没有把 Kam 标为 KPM 编译 SDK，也没有引入它的模板代码、Shell 服务或 MCP 服务。将来若增加用户态安装 ZIP，可以另行用 Kam 管理包装项目；不影响本次原生 KPM 仓库的构建与交付。

Kam README 将项目标为 MIT，联系段落列出作者 LightJunction；固定版本的 `LICENSE` 仅写有 `Copyright (c) 2025`，未列出姓名。本仓库记录实际内容，不补写版权持有人，也没有复制其代码需要另行纳入许可文本。[README 作者](https://github.com/MemDeco-WG/Kam/blob/3835842ca90cefc621383e72e01078481122aa30/README.md#L313-L328)、[LICENSE 原文](https://github.com/MemDeco-WG/Kam/blob/3835842ca90cefc621383e72e01078481122aa30/LICENSE#L1-L10)
