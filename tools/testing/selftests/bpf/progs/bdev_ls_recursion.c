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
} bdev_map_a SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_BDEV_STORAGE);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, int);
	__type(value, long);
} bdev_map_b SEC(".maps");

extern void *bpf_bdev_storage_get(struct bpf_map *map,
				   struct block_device *bdev,
				   __u64 flags) __ksym __weak;
extern int bpf_bdev_storage_delete(struct bpf_map *map,
				    struct block_device *bdev) __ksym __weak;

int map_a_ok = 0;
int map_b_ok = 0;
int delete_ok = 0;
int recreate_ok = 0;

/*
 * Sequential kfunc calls within a single BPF program.
 *
 * Each bpf_bdev_storage_get/delete call independently acquires and releases
 * the per-cpu busy counter. Sequential calls should NOT trigger the busy
 * counter (they are not nested).
 *
 * Pattern: get(map_a, CREATE) -> delete(map_a) -> get(map_a, CREATE) ->
 *          get(map_b, CREATE)
 */
SEC("lsm/bdev_alloc_security")
int BPF_PROG(bdev_recursion_test, struct block_device *bdev)
{
	long *ptr;
	int ret;

	/* Step 1: create on map_a */
	ptr = bpf_bdev_storage_get((struct bpf_map *)&bdev_map_a, bdev,
				    BPF_LOCAL_STORAGE_GET_F_CREATE);
	if (ptr) {
		*ptr = 200;
		map_a_ok = 1;
	}

	/* Step 2: delete map_a */
	ret = bpf_bdev_storage_delete((struct bpf_map *)&bdev_map_a, bdev);
	if (ret == 0)
		delete_ok = 1;

	/* Step 3: re-create on map_a (after delete) */
	ptr = bpf_bdev_storage_get((struct bpf_map *)&bdev_map_a, bdev,
				    BPF_LOCAL_STORAGE_GET_F_CREATE);
	if (ptr) {
		*ptr = 201;
		recreate_ok = 1;
	}

	/* Step 4: create on map_b */
	ptr = bpf_bdev_storage_get((struct bpf_map *)&bdev_map_b, bdev,
				    BPF_LOCAL_STORAGE_GET_F_CREATE);
	if (ptr) {
		*ptr = 100;
		map_b_ok = 1;
	}

	return 0;
}
