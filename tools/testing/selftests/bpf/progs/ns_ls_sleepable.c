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
} ns_map SEC(".maps");

extern void *bpf_ns_storage_get(struct bpf_map *map, struct ns_common *ns,
				__u64 flags) __ksym __weak;
extern struct ns_common *bpf_get_current_ns(__u64 ns_type) __ksym __weak;
extern void bpf_rcu_read_lock(void) __ksym;
extern void bpf_rcu_read_unlock(void) __ksym;

#define CLONE_NEWUTS 0x04000000

pid_t target_pid = 0;
int get_success = 0;
__u64 read_value = 0;

/*
 * Sleepable LSM program accessing NS_STORAGE.
 */
SEC("?lsm.s/file_open")
int BPF_PROG(sleepable_ns_storage, struct file *file)
{
	struct task_struct *task = bpf_get_current_task_btf();
	struct ns_common *ns;
	long *ptr;

	if (task->pid != target_pid)
		return 0;

	bpf_rcu_read_lock();

	ns = bpf_get_current_ns(CLONE_NEWUTS);
	if (!ns)
		goto out;
	ptr = bpf_ns_storage_get((struct bpf_map *)&ns_map, ns,
				 BPF_LOCAL_STORAGE_GET_F_CREATE);
	if (ptr) {
		*ptr = 0x0A110C03;
		get_success = 1;
	}

	ptr = bpf_ns_storage_get((struct bpf_map *)&ns_map, ns, 0);
	if (ptr)
		read_value = *ptr;

out:
	bpf_rcu_read_unlock();
	return 0;
}
