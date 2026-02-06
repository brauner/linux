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
 * This program MUST fail to load. It uses a socket filter
 * (BPF_PROG_TYPE_SOCKET_FILTER), but the bdev_storage kfuncs
 * are registered only for BPF_PROG_TYPE_LSM. The verifier
 * rejects the kfunc call from an unauthorized program type.
 */
SEC("socket")
int negative_socket(void *ctx)
{
	struct block_device *bdev = NULL;

	(void)bpf_bdev_storage_get((struct bpf_map *)&bdev_map, bdev,
				    BPF_LOCAL_STORAGE_GET_F_CREATE);
	return 0;
}
