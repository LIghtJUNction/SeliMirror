# 行为与移植边界

本模块移植固定版本 ReSukiSU 的“隐藏 SELinux 修改”逻辑，目标是给符合 UID 条件的调用提供一份独立策略的查询结果，同时保留真实内核的权限检查和进程上下文转换。对应上游现名 BakaSU；四个项目的完整版本及许可证见 [UPSTREAM.md](../UPSTREAM.md)。本文描述实现行为；真机结果须按[验证计划](validation-plan.md)记录。

## 适配范围

目标是 `Laulan56/android_kernel_xiaomi_sm8150` 的 `miui` 提交 `bd65f57d4c36882a5dfd34557e64198516ed392b`，Linux 4.14.268、arm64。这个分支带有较新 SELinux API 的回移：查询函数接收 `struct selinux_state *`，`selinux_ss` 保存一个 SID 表指针。因此本模块使用目标内核的真实头文件及构建配置，不能以普通上游 4.14 的结构布局替代。[state 定义][kernel-state]、[ss 定义][kernel-ss]

交付中的参考构建采用 `raphael_stock` 配置并进行构建所需的规范化；用户尚未提供正在运行的 `.config`。模块的版本、必要符号和部分运行时结构偏移检查用于拒绝已知不匹配，不能证明所有配置和布局一致。其他 sm8150 设备或同为 4.14 的内核，需要按实际内核重新构建和验证。

## 四个应用可见接口

| 接口 | 固定版本上游行为 | 本 KPM 的接入点 |
|---|---|---|
| `/sys/fs/selinux/context` | 先检查真实 `CHECK_CONTEXT` 权限，再按备份策略验证并返回规范化上下文。[实现][up-context] | 包装 `sel_write_context`，保留外层 selinuxfs 事务处理。 |
| `/sys/fs/selinux/access` | 先检查真实 `COMPUTE_AV` 权限，用备份策略处理两个上下文并计算完整决策，固定 `seqno=1`。[实现][up-access] | 包装 `sel_write_access`，使用私有策略调用目标内核的权限计算服务。 |
| `/proc/.../attr/current` 写入 | 只处理属性名 `current`；先检查真实 `SETCURRENT`，要求备份与真实策略均接受上下文，再执行真实的动态转换、线程和 ptrace 检查。[实现][up-current] | 包装 `selinux_setprocattr`，完成权限与私有策略预检后交还原函数，由原函数登记真实 SID 和提交凭据。 |
| `/sys/fs/selinux/status` 的读取和映射 | 在打开文件时选择副本页，之后原生 `read`/`mmap` 使用这张页。[实现][up-status-open] | 包装 `selinux_kernel_status_page`，仅对真实全局 SELinux state 的匹配调用返回模块页；原生 open/read/mmap 继续处理句柄和映射。 |

覆盖这四处是本移植的依据。`access` 的结果来自策略引擎，包括类型、属性、条件规则、约束及 permissive 标志，不是单独对某个类型名返回固定错误。[上游权限计算][up-compute]、[目标用户态查询服务][kernel-compute]

本模块不会把私有策略装入真实策略引擎，也不修改真实 AVC 的放行规则。真实进程转换仍由目标内核决定；私有策略预检会额外拒绝仅在实时修改策略中存在的上下文。这里的四接口覆盖并不等于 Hunter 6.72 的全部实现已被分析或已经通过真机测试。

## UID 条件与调用时机

四处均沿用原始真实 UID `current_uid() >= 10000`，对应本模块的 `rsk_is_app()`。不读取有效 UID，不按 `100000` 取余，也不按包名、进程名或 root 授权名单筛选。[context/access UID 条件][up-context-uid]、[current UID 条件][up-current]、[status UID 条件][up-status-open]

- 真实 UID 0 或 9999：交给原处理函数。
- 真实 UID 10000，即使有效 UID 为 0：仍进入模块路径。
- 真实 UID 100001：仍匹配；这也会覆盖某些第二用户中的系统身份，不能把该条件解释为 Android appId 检查。

`context`、`access` 和 `current` 按实际写入时的调用者判断。`status` 在打开文件时选择页面，之后转交 FD、改变 UID 或切换开关都不会重新选择该 FD 的页面。模块未启用、基线未就绪，或 KernelPatch 同一链中的先前回调已设置 `skip_origin` 时，本模块回调直接返回。

## 干净策略从哪里来

ReSukiSU 在 `apply_kernelsu_rules()` 中先复制实时策略并初始化独立 SID 表，然后才加入自己的类型、permissive 和 allow 规则。对应启动路径在 init 第二阶段调用这段逻辑。[备份与规则添加顺序][up-backup]、[第二阶段调用][up-second-stage]

独立 KPM 无法从已经被修改的实时策略可靠地恢复这份备份，因此提供两种明确的输入方式：

| 加载参数 | 条件与结果 |
|---|---|
| 无参数或 `capture` | 必须在真实 SELinux state 首次初始化前装入；过晚返回 `-EAGAIN`。记录首次成功 `security_load_policy` 调用的输入二进制，构造私有策略。等待期间状态为 `armed`，四个应用接口继续原生处理。 |
| `policy=/绝对路径` | 用于真实策略已经初始化的环境；过早返回 `-EAGAIN`。读取明确提供的策略二进制并在加载时构造私有策略。 |

capture 捕获的是首次加载的**输入字节**，ReSukiSU 备份的是稍后添加自身规则前的**实时策略内容**。当这两个时间点之间没有其他合法策略重载或 boolean 修改时，二者通常代表预期的同一基线；发生这些变化时不能认为两份策略必然相同。其他组件若已修改首次加载的输入，capture 也无法识别并还原修改。文件模式允许选择经过核对的对应快照。

原生首次加载失败时，capture 保留错误码并继续等待后续加载；原生加载成功但私有副本构造失败时，状态转为 `error`，不会使用实时策略作为替代品。输入上限为 32 MiB。成功发布后的策略内容固定，后续真实策略重载和 boolean 修改不会同步到该副本；查询过程中仅会按需要增加私有 SID 表条目。

文件模式要求绝对路径、普通文件、大小大于 0 且不超过 32 MiB；使用 `O_NOFOLLOW` 禁止最后一级路径为符号链接，按记录长度完整读取并检查额外字节。直接指定 `/sys/fs/selinux/policy` 会被拒绝。**这些检查不能认证文件来源，也不能证明它与当前系统匹配**：从已修改策略导出的普通文件，或其他系统的格式合法策略，仍可能通过解析。应自行核对系统版本和策略摘要，不能把“解析成功”写成“已确认原厂策略”。

## 私有策略与真实 SID 的分工

`src/policy.c` 分配独立的 `selinux_state`、`selinux_ss`、`policydb` 和 SID 表，通过 `policydb_read()`、`policydb_load_isids()` 初始化。只有 `security_context_to_sid()`、`security_sid_to_context()`、`security_compute_av_user()` 三类查询服务可使用这份 state。私有 state 的 AVC、类映射和 status 锁不用于真实内核操作；不能将它传给会更新全局状态的 `security_load_policy()` 或 `selinux_ss_init()`。[目标策略加载路径][kernel-load]

同一段上下文在两张 SID 表中的数字可能不同。私有 SID 只用于私有策略的规范化与权限计算，不能写入真实进程凭据。普通 `context/access` 查询在私有转换成功后，仍尝试向真实 SID 表登记同一上下文；此处保留上游有意设置的副作用，不代表增加真实策略规则。[上游双表转换][up-sid]

| 情况 | 返回与副作用 |
|---|---|
| 真实接口权限检查失败 | 立即返回该错误；不解析输入，不转换或登记 SID。 |
| 私有上下文转换失败 | 立即返回私有错误；本实现不再尝试登记该上下文的真实 SID。 |
| 私有转换成功，真实转换失败，接口为 `context/access` | 忽略真实转换错误，继续按私有策略产生查询结果。 |
| access 源上下文成功、目标上下文失败 | 返回目标错误；源上下文先前的真实 SID 登记允许保留。 |
| 接口为 `current` | 私有预检成功后调用原生处理；真实上下文转换和后续转换检查也必须成功，才能提交真实凭据。 |

所以“只对私有策略接受的上下文尝试真实 SID 登记”与“普通查询必须在真实策略中转换成功”是不同要求。本实现遵循前者；后者会改变上游 `context/access` 的错误语义。

## 输入、输出与错误顺序

### context 和 access

真实权限检查优先于格式与上下文检查。`context` 返回私有策略规范化后的完整字符串，回调返回长度**包含结尾 NUL**；长度等于事务容量时允许，超过容量为 `-ERANGE`。[上游长度处理][up-context-length]

`access` 采用有长度边界的解析器，匹配目标内核 `sscanf("%s %s %hu")` 的有效转换行为：十进制前缀、拒绝 `+/-`、截取为 16 位、不要求耗尽尾部输入，并保留目标字符表把 `0xA0` 视为空白的行为。类号 0 或超出策略类表不会在解析层增加额外拒绝，由内核决策服务处理。具体异常输入见[验证计划](validation-plan.md)。[上游格式][up-access-parse]、[目标 scanf][kernel-scanf]、[字符表][kernel-ctype]

access 的文本格式为 `allowed ffffffff auditallow auditdeny 1 flags`，除序号外均用无前缀十六进制；返回长度不包含 NUL，不添加换行。`seqno` 明确设为 1，不能使用实时策略的加载序号。容量不足时本实现返回 `-ERANGE`，不把截断输出当成成功；正常内核事务容量足以容纳全部六字段。[上游格式与序号][up-access-result]

输入长度和输出容量分别传递。目标 4 KiB 页、arm64 的 `SIMPLE_TRANSACTION_LIMIT` 为 4088 字节，最大输入为 4087 字节。回调返回的是响应长度；外层成功 `write()` 返回原输入长度，后续 `read()` 取得响应。同一 FD 的第二次写入 `-EBUSY`、过大输入 `-EFBIG` 等外层行为由原生事务实现保留。[容量定义][kernel-capacity]、[事务分配][kernel-transaction]、[selinuxfs 外层返回][kernel-write]

### current

只在输入非空、首字节非 NUL 且非换行时做上下文预检。若最后一字节为 `\n`，预检将其改成 NUL，并把长度减少 1；随后把**已修改缓冲区与已减少长度**一起交给原生函数。合法单末尾换行输入不会被缩短两次。空输入、单独换行和 NUL 开头的输入交由原函数完成原有错误路径，不能伪造成功。[上游处理][up-current]、[目标原生处理][kernel-current]

本实现先做一次真实 `SETCURRENT` 检查，私有验证通过后，原生 `selinux_setprocattr()` 会再检查一次 `SETCURRENT`。这样保留了权限错误优先及目标内核的凭据、动态转换、线程边界、ptrace 处理，但与上游直接实现转换流程存在两项差异：允许审计可能出现两次；两次检查之间若真实策略发生变化，第二次可能返回新的错误。这里不承诺跨两次检查的原子快照。[目标转换检查][kernel-current-transition]

### 内存不足的限定

上游先分配两个上下文副本；备份字符串解析成功后，即使后续备份 SID 的散列或登记失败，仍可能继续登记真实 SID。本实现先完成私有 SID 转换，失败即返回，因此少了这一项错误路径副作用。access 的有界解析也省去了上游两个 `size + 1` 临时缓冲区。两处改变会影响内存不足时的分配次数、失败位置和部分 SID 副作用，不能宣称 OOM 条件下逐项相同。[上游分配与登记顺序][up-sid]、[上游 access 分配][up-access-parse]

## status、开关与卸载

模块状态页固定为 `version=1`、`sequence=0`、`enforcing=1`、`policyload=0`，`deny_unknown` 来自私有策略的 `!allow_unknown`。这采用上游针对 4.14 晚加载的规范化值；上游早期模式会复制当时真实页且可能因非 enforcing 而跳过，因此不能把本模块两种加载模式都说成逐字复制上游早期快照。[上游状态初始化][up-status-image]、[目标状态页初始化][kernel-status]

原生 `read` 和只读单页 `mmap` 使用同一页；非零映射偏移或非一页长度返回 `-EIO`，可写映射返回 `-EPERM`，并清除 `VM_MAYWRITE`。`off` 或卸载只改变**未来打开**的 status 文件；已有私有 FD 和映射仍持有旧快照，已有真实 FD 也不会因 `on` 被替换。[目标 open/read/mmap][kernel-status-file]

控制命令 `on` 要求基线已经就绪；`off` 关闭新进入的查询路径。成功响应完整复制到调用者后才改变开关，响应容量不足或复制失败不会改变开关。已进入的查询可以正常结束。`status` 中各接口计数仅表示回调命中次数，不能据此证明返回正确或检测通过。

模块支持卸载：关闭常驻入口，等待在途回调结束，再从 KernelPatch 链中移除本模块回调并释放私有策略。使用 `hook_unwrap_remove(..., 0)` 有意保留链和 trampoline；已经发布的入口页、已对外返回的状态页保留到重启，避免分发器旧地址或已有 FD/PFN 映射引用释放后的内存。这是有明确内存代价的退出方式，不能把成功卸载描述为恢复所有原始指令或回收全部内存。[KernelPatch 链移除实现][kp-unhook]

加载、控制和卸载管理操作应串行；普通应用查询可以并发。固定版本 KernelPatch 的 `module_control0()` 共用 `mod->ctl_args`，未提供并发控制调用的互斥，本模块也不能在进入自身回调之后修复该外层竞争。[KernelPatch 控制入口][kp-control]

[up-context]: https://github.com/Baka-SU/BakaSU/blob/896e8981e0ed76ec14d1dcb39ab793438b304886/kernel/feature/selinux_hide.c#L240-L302
[up-context-uid]: https://github.com/Baka-SU/BakaSU/blob/896e8981e0ed76ec14d1dcb39ab793438b304886/kernel/feature/selinux_hide.c#L240-L308
[up-context-length]: https://github.com/Baka-SU/BakaSU/blob/896e8981e0ed76ec14d1dcb39ab793438b304886/kernel/feature/selinux_hide.c#L1310-L1362
[up-access]: https://github.com/Baka-SU/BakaSU/blob/896e8981e0ed76ec14d1dcb39ab793438b304886/kernel/feature/selinux_hide.c#L304-L395
[up-access-parse]: https://github.com/Baka-SU/BakaSU/blob/896e8981e0ed76ec14d1dcb39ab793438b304886/kernel/feature/selinux_hide.c#L316-L335
[up-access-result]: https://github.com/Baka-SU/BakaSU/blob/896e8981e0ed76ec14d1dcb39ab793438b304886/kernel/feature/selinux_hide.c#L387-L390
[up-current]: https://github.com/Baka-SU/BakaSU/blob/896e8981e0ed76ec14d1dcb39ab793438b304886/kernel/feature/selinux_hide.c#L449-L549
[up-status-open]: https://github.com/Baka-SU/BakaSU/blob/896e8981e0ed76ec14d1dcb39ab793438b304886/kernel/feature/selinux_hide.c#L554-L578
[up-status-image]: https://github.com/Baka-SU/BakaSU/blob/896e8981e0ed76ec14d1dcb39ab793438b304886/kernel/feature/selinux_hide.c#L1017-L1059
[up-backup]: https://github.com/Baka-SU/BakaSU/blob/896e8981e0ed76ec14d1dcb39ab793438b304886/kernel/selinux/rules.c#L185-L244
[up-second-stage]: https://github.com/Baka-SU/BakaSU/blob/896e8981e0ed76ec14d1dcb39ab793438b304886/kernel/runtime/ksud_integration.c#L269-L281
[up-sid]: https://github.com/Baka-SU/BakaSU/blob/896e8981e0ed76ec14d1dcb39ab793438b304886/kernel/feature/selinux_hide.c#L1219-L1300
[up-compute]: https://github.com/Baka-SU/BakaSU/blob/896e8981e0ed76ec14d1dcb39ab793438b304886/kernel/feature/selinux_hide.c#L1414-L1824
[kernel-state]: https://github.com/Laulan56/android_kernel_xiaomi_sm8150/blob/bd65f57d4c36882a5dfd34557e64198516ed392b/security/selinux/include/security.h#L98-L116
[kernel-ss]: https://github.com/Laulan56/android_kernel_xiaomi_sm8150/blob/bd65f57d4c36882a5dfd34557e64198516ed392b/security/selinux/ss/services.h#L26-L34
[kernel-compute]: https://github.com/Laulan56/android_kernel_xiaomi_sm8150/blob/bd65f57d4c36882a5dfd34557e64198516ed392b/security/selinux/ss/services.c#L1164-L1214
[kernel-load]: https://github.com/Laulan56/android_kernel_xiaomi_sm8150/blob/bd65f57d4c36882a5dfd34557e64198516ed392b/security/selinux/ss/services.c#L2129-L2284
[kernel-scanf]: https://github.com/Laulan56/android_kernel_xiaomi_sm8150/blob/bd65f57d4c36882a5dfd34557e64198516ed392b/lib/vsprintf.c#L2861-L3145
[kernel-ctype]: https://github.com/Laulan56/android_kernel_xiaomi_sm8150/blob/bd65f57d4c36882a5dfd34557e64198516ed392b/lib/ctype.c#L12-L38
[kernel-capacity]: https://github.com/Laulan56/android_kernel_xiaomi_sm8150/blob/bd65f57d4c36882a5dfd34557e64198516ed392b/include/linux/fs.h#L3337-L3342
[kernel-transaction]: https://github.com/Laulan56/android_kernel_xiaomi_sm8150/blob/bd65f57d4c36882a5dfd34557e64198516ed392b/fs/libfs.c#L738-L766
[kernel-write]: https://github.com/Laulan56/android_kernel_xiaomi_sm8150/blob/bd65f57d4c36882a5dfd34557e64198516ed392b/security/selinux/selinuxfs.c#L779-L798
[kernel-current]: https://github.com/Laulan56/android_kernel_xiaomi_sm8150/blob/bd65f57d4c36882a5dfd34557e64198516ed392b/security/selinux/hooks.c#L6174-L6244
[kernel-current-transition]: https://github.com/Laulan56/android_kernel_xiaomi_sm8150/blob/bd65f57d4c36882a5dfd34557e64198516ed392b/security/selinux/hooks.c#L6268-L6311
[kernel-status]: https://github.com/Laulan56/android_kernel_xiaomi_sm8150/blob/bd65f57d4c36882a5dfd34557e64198516ed392b/security/selinux/ss/status.c#L45-L75
[kernel-status-file]: https://github.com/Laulan56/android_kernel_xiaomi_sm8150/blob/bd65f57d4c36882a5dfd34557e64198516ed392b/security/selinux/selinuxfs.c#L219-L270
[kp-unhook]: https://github.com/bmax121/KernelPatch/blob/ef52c62b339bd2da51880922249bf4edef71b1cf/kernel/base/hook.c#L726-L799
[kp-control]: https://github.com/bmax121/KernelPatch/blob/ef52c62b339bd2da51880922249bf4edef71b1cf/kernel/patch/module/module.c#L618-L657
