// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2026 Christian Brauner (Amutable) <brauner@kernel.org> */

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char _license[] SEC("license") = "GPL";

struct ns_storage_val {
	__u64 cookie;
};

struct {
	__uint(type, BPF_MAP_TYPE_NS_STORAGE);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, __u64);
	__type(value, struct ns_storage_val);
} ns_map SEC(".maps");

extern void *bpf_ns_storage_get(struct bpf_map *map, struct ns_common *ns,
				__u64 flags) __ksym __weak;

/*
 * Can't call bpf_ns_storage_get() from untrusted hook
 */
SEC("?lsm/namespace_free")
void BPF_PROG(ns_free_untrusted_storage, struct ns_common *ns)
{
	bpf_ns_storage_get((struct bpf_map *)&ns_map, ns, 0);
}
