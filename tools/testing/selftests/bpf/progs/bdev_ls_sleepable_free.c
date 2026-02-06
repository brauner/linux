// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2026 Christian Brauner (Amutable) <brauner@kernel.org> */

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char _license[] SEC("license") = "GPL";

struct {
	__uint(type, BPF_MAP_TYPE_BDEV_STORAGE);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, int);
	__type(value, long);
} bdev_map SEC(".maps");

extern void *bpf_bdev_storage_get(struct bpf_map *map,
				   struct block_device *bdev,
				   __u64 flags) __ksym;

/*
 * This program MUST fail to load. bdev_free_security is NOT in the
 * sleepable_lsm_hooks set because it runs from an RCU callback
 * (bdev_free_inode). The verifier rejects sleepable programs for
 * non-sleepable hooks.
 */
SEC("lsm.s/bdev_free_security")
void BPF_PROG(sleepable_bdev_free, struct block_device *bdev)
{
	(void)bpf_bdev_storage_get((struct bpf_map *)&bdev_map, bdev, 0);
}
