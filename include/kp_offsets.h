/* SPDX-License-Identifier: GPL-2.0-or-later */
/* KernelPatch ef52c62, kernel/linux/include/linux/{cred,sched}.h.
 * Copyright (C) 2023 bmax121. Values describe the RUNNING kernel.
 */
#ifndef RSK_KP_OFFSETS_H
#define RSK_KP_OFFSETS_H
#include <linux/types.h>

struct rsk_kp_cred_offsets {
	s16 usage, subscribers, magic;
	s16 uid, gid, suid, sgid, euid, egid, fsuid, fsgid;
	s16 securebits, cap_inheritable, cap_permitted, cap_effective, cap_bset, cap_ambient;
	s16 user, user_ns, ucounts, group_info;
	s16 session_keyring, process_keyring, thread_keyring, request_key_auth;
	s16 security, rcu;
};

struct rsk_kp_task_offsets {
	s16 pid, tgid, thread_pid, ptracer_cred, real_cred, cred;
	s16 comm, fs, files, loginuid, sessionid, seccomp, security;
	s16 stack, tasks, mm, active_mm;
};

_Static_assert(sizeof(struct rsk_kp_cred_offsets) == 54, "KP cred offset ABI");
_Static_assert(sizeof(struct rsk_kp_task_offsets) == 34, "KP task offset ABI");
#endif
