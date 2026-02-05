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
				__u64 flags) __ksym;
extern struct ns_common *bpf_get_current_ns(__u64 ns_type) __ksym;

#define CLONE_NEWUTS 0x04000000

/*
 * This program MUST fail to load. It uses a socket filter
 * (BPF_PROG_TYPE_SOCKET_FILTER -> BTF_KFUNC_HOOK_SOCKET_FILTER),
 * but the ns_storage kfuncs are registered for BPF_PROG_TYPE_LSM
 * (BTF_KFUNC_HOOK_TRACING). Since non-weak __ksym kfuncs must
 * resolve, the load should fail.
 */
SEC("socket")
int negative_socket(void *ctx)
{
	struct ns_common *ns;

	ns = bpf_get_current_ns(CLONE_NEWUTS);
	if (!ns)
		return 0;

	(void)bpf_ns_storage_get((struct bpf_map *)&ns_map, ns,
				 BPF_LOCAL_STORAGE_GET_F_CREATE);
	return 0;
}
