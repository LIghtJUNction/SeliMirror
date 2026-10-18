/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef RSK_KERNEL_API_H
#define RSK_KERNEL_API_H

#include <linux/types.h>
#include <linux/gfp.h>
#include <linux/fs.h>

struct policydb;
struct sidtab;
struct selinux_state;
struct av_decision;
struct common_audit_data;

/* KernelPatch resolves its own exports, not arbitrary kernel imports.
 * Every native function below is resolved from the running kernel by name.
 */
struct rsk_kernel_api {
	struct selinux_state *live_state;
	const char *linux_banner;
	void *(*kmalloc)(size_t, gfp_t);
	void (*kfree)(const void *);
	void *(*vmalloc)(unsigned long);
	void *(*vmalloc_user)(unsigned long);
	void (*vfree)(const void *);
	struct page *(*vmalloc_to_page)(const void *);
	void *(*memset)(void *, int, size_t);
	void *(*memcpy)(void *, const void *, size_t);
	int (*snprintf)(char *, size_t, const char *, ...);
	int (*printk)(const char *, ...);
	int (*policydb_read)(struct policydb *, void *);
	void (*policydb_destroy)(struct policydb *);
	int (*policydb_load_isids)(struct policydb *, struct sidtab *);
	void (*sidtab_destroy)(struct sidtab *);
	int (*context_to_sid)(struct selinux_state *, const char *, u32, u32 *, gfp_t);
	int (*sid_to_context)(struct selinux_state *, u32, char **, u32 *);
	void (*compute_av_user)(struct selinux_state *, u32, u32, u16, struct av_decision *);
	int (*avc_has_perm)(struct selinux_state *, u32, u32, u16, u32,
			    struct common_audit_data *);
	struct file *(*filp_open)(const char *, int, umode_t);
	int (*filp_close)(struct file *, fl_owner_t);
	ssize_t (*kernel_read)(struct file *, void *, size_t, loff_t *);
	void *(*module_alloc)(unsigned long);
	void (*flush_icache_range)(unsigned long, unsigned long);
	void (*kick_all_cpus_sync)(void);
	void (*msleep)(unsigned int);
	void (*synchronize_rcu)(void);
};

extern struct rsk_kernel_api rsk_api;
int rsk_api_init(void);

#endif
