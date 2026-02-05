// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2026 Christian Brauner (Amutable) <brauner@kernel.org> */

#include "vmlinux.h"
#include <errno.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char _license[] SEC("license") = "GPL";

#define CLONE_NEWUTS 0x04000000
#define CLONE_NEWIPC 0x08000000

struct ns_storage_val {
	__u64 cookie;
};

struct {
	__uint(type, BPF_MAP_TYPE_NS_STORAGE);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, __u64);
	__type(value, struct ns_storage_val);
} ns_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_NS_STORAGE);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, __u64);
	__type(value, __u64);
} ns_map_b SEC(".maps");

extern void *bpf_ns_storage_get(struct bpf_map *map, struct ns_common *ns,
				__u64 flags) __ksym __weak;
extern int bpf_ns_storage_delete(struct bpf_map *map,
				 struct ns_common *ns) __ksym __weak;
extern struct ns_common *bpf_get_current_ns(__u64 ns_type) __ksym __weak;

/* Shared state with userspace */
pid_t target_pid = 0;
int deny_alloc_active = 0;
int kfunc_get_success = 0;
int kfunc_delete_success = 0;
__u64 kfunc_read_value = 0;
int alloc_storage_active = 0;
int alloc_storage_ok = 0;
__u64 alloc_storage_value = 0;
int multi_map_a_ok = 0;
int multi_map_b_ok = 0;
int ipc_get_success = 0;
__u64 ipc_read_value = 0;

/*
 * namespace_alloc: deny variant. Returns -EPERM to block creation.
 */
SEC("?lsm/namespace_alloc")
int BPF_PROG(ns_alloc_deny, struct ns_common *ns)
{
	if (!deny_alloc_active)
		return 0;
	if (ns->ns_type == CLONE_NEWUTS)
		return -EPERM;
	return 0;
}

SEC("?lsm/namespace_alloc")
int BPF_PROG(ns_alloc_storage, struct ns_common *ns)
{
	struct ns_storage_val *val;

	if (!alloc_storage_active)
		return 0;
	if (ns->ns_type != CLONE_NEWUTS)
		return 0;

	val = bpf_ns_storage_get((struct bpf_map *)&ns_map, ns,
				 BPF_LOCAL_STORAGE_GET_F_CREATE);
	if (val) {
		val->cookie = 0x0A110C06;
		alloc_storage_ok = 1;
		alloc_storage_value = val->cookie;
	}
	return 0;
}

/*
 * file_open: kfunc CREATE + DELETE test.
 * Uses bpf_get_current_ns() to get an RCU-protected ns_common pointer.
 */
SEC("?lsm/file_open")
int BPF_PROG(ns_kfunc_test, struct file *file)
{
	struct task_struct *task = bpf_get_current_task_btf();
	struct ns_storage_val *val;
	struct ns_common *ns;
	int ret;

	if (task->pid != target_pid)
		return 0;

	ns = bpf_get_current_ns(CLONE_NEWUTS);
	if (!ns)
		return 0;

	val = bpf_ns_storage_get((struct bpf_map *)&ns_map, ns,
				 BPF_LOCAL_STORAGE_GET_F_CREATE);
	if (val) {
		val->cookie = 0x0A110C01;
		kfunc_get_success = 1;
		kfunc_read_value = val->cookie;

		ret = bpf_ns_storage_delete((struct bpf_map *)&ns_map, ns);
		if (ret == 0)
			kfunc_delete_success = 1;
	}
	return 0;
}

/*
 * file_open: multi-map test.
 * Creates storage on two maps for the same namespace.
 */
SEC("?lsm/file_open")
int BPF_PROG(ns_multi_map_test, struct file *file)
{
	struct task_struct *task = bpf_get_current_task_btf();
	struct ns_storage_val *val_a;
	struct ns_common *ns;
	__u64 *val_b;

	if (task->pid != target_pid)
		return 0;

	ns = bpf_get_current_ns(CLONE_NEWUTS);
	if (!ns)
		return 0;

	val_a = bpf_ns_storage_get((struct bpf_map *)&ns_map, ns,
				   BPF_LOCAL_STORAGE_GET_F_CREATE);
	if (val_a) {
		val_a->cookie = 0x0A110C02;
		multi_map_a_ok = 1;
	}

	val_b = bpf_ns_storage_get((struct bpf_map *)&ns_map_b, ns,
				   BPF_LOCAL_STORAGE_GET_F_CREATE);
	if (val_b) {
		*val_b = 0x42;
		multi_map_b_ok = 1;
	}

	return 0;
}

/*
 * file_open: IPC namespace test.
 * Exercises bpf_get_current_ns() with CLONE_NEWIPC to verify
 * storage works across different namespace types.
 */
SEC("?lsm/file_open")
int BPF_PROG(ns_ipc_test, struct file *file)
{
	struct task_struct *task = bpf_get_current_task_btf();
	struct ns_storage_val *val;
	struct ns_common *ns;

	if (task->pid != target_pid)
		return 0;

	ns = bpf_get_current_ns(CLONE_NEWIPC);
	if (!ns)
		return 0;

	val = bpf_ns_storage_get((struct bpf_map *)&ns_map, ns,
				 BPF_LOCAL_STORAGE_GET_F_CREATE);
	if (val) {
		val->cookie = 0x0A110C05;
		ipc_get_success = 1;
		ipc_read_value = val->cookie;
	}

	return 0;
}
