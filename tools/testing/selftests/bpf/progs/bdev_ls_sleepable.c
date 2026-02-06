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
				   __u64 flags) __ksym __weak;
extern void bpf_rcu_read_lock(void) __ksym;
extern void bpf_rcu_read_unlock(void) __ksym;

int get_success = 0;
__u64 read_value = 0;

/*
 * Sleepable LSM program accessing BDEV_STORAGE.
 * BPF_MAP_TYPE_BDEV_STORAGE is in the sleepable-compatible map list.
 * Explicit bpf_rcu_read_lock() is required in sleepable programs
 * (non-sleepable LSM progs hold RCU implicitly) since the kfuncs
 * require RCU protection.
 */
SEC("?lsm.s/bdev_alloc_security")
int BPF_PROG(sleepable_bdev_storage, struct block_device *bdev)
{
	long *ptr;

	bpf_rcu_read_lock();

	ptr = bpf_bdev_storage_get((struct bpf_map *)&bdev_map, bdev,
				    BPF_LOCAL_STORAGE_GET_F_CREATE);
	if (ptr) {
		*ptr = 0x0A110C03;
		get_success = 1;
	}

	ptr = bpf_bdev_storage_get((struct bpf_map *)&bdev_map, bdev, 0);
	if (ptr)
		read_value = *ptr;

	bpf_rcu_read_unlock();
	return 0;
}
