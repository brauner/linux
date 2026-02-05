// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2026 Christian Brauner (Amutable) <brauner@kernel.org> */

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char _license[] SEC("license") = "GPL";

struct {
	__uint(type, BPF_MAP_TYPE_NS_STORAGE);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, __u64);
	__type(value, long);
} ns_map_a SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_NS_STORAGE);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, __u64);
	__type(value, long);
} ns_map_b SEC(".maps");

extern void *bpf_ns_storage_get(struct bpf_map *map, struct ns_common *ns,
				__u64 flags) __ksym __weak;
extern int bpf_ns_storage_delete(struct bpf_map *map,
				 struct ns_common *ns) __ksym __weak;
extern struct ns_common *bpf_get_current_ns(__u64 ns_type) __ksym __weak;

#define CLONE_NEWUTS 0x04000000

pid_t target_pid = 0;
int map_a_ok = 0;
int map_b_ok = 0;
int delete_ok = 0;
int recreate_ok = 0;

/*
 * Sequential kfunc calls within a single BPF program.
 */
SEC("lsm/file_open")
int BPF_PROG(ns_recursion_test, struct file *file)
{
	struct task_struct *task = bpf_get_current_task_btf();
	struct ns_common *ns;
	long *ptr;
	int ret;

	if (task->pid != target_pid)
		return 0;

	ns = bpf_get_current_ns(CLONE_NEWUTS);
	if (!ns)
		return 0;

	/* Step 1: create on map_a */
	ptr = bpf_ns_storage_get((struct bpf_map *)&ns_map_a, ns,
				 BPF_LOCAL_STORAGE_GET_F_CREATE);
	if (ptr) {
		*ptr = 200;
		map_a_ok = 1;
	}

	/* Step 2: delete map_a */
	ret = bpf_ns_storage_delete((struct bpf_map *)&ns_map_a, ns);
	if (ret == 0)
		delete_ok = 1;

	/* Step 3: re-create on map_a (after delete) */
	ptr = bpf_ns_storage_get((struct bpf_map *)&ns_map_a, ns,
				 BPF_LOCAL_STORAGE_GET_F_CREATE);
	if (ptr) {
		*ptr = 201;
		recreate_ok = 1;
	}

	/* Step 4: create on map_b */
	ptr = bpf_ns_storage_get((struct bpf_map *)&ns_map_b, ns,
				 BPF_LOCAL_STORAGE_GET_F_CREATE);
	if (ptr) {
		*ptr = 100;
		map_b_ok = 1;
	}

	return 0;
}
