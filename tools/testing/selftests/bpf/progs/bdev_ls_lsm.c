// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2026 Christian Brauner (Amutable) <brauner@kernel.org> */

#include "vmlinux.h"
#include <errno.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char _license[] SEC("license") = "GPL";

struct bdev_storage_val {
	__u64 cookie;
};

struct {
	__uint(type, BPF_MAP_TYPE_BDEV_STORAGE);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, int);
	__type(value, struct bdev_storage_val);
} bdev_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_BDEV_STORAGE);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, int);
	__type(value, __u64);
} bdev_map_b SEC(".maps");

extern void *bpf_bdev_storage_get(struct bpf_map *map,
				   struct block_device *bdev,
				   __u64 flags) __ksym __weak;
extern int bpf_bdev_storage_delete(struct bpf_map *map,
				    struct block_device *bdev) __ksym __weak;
extern struct block_device *bpf_get_file_bdev(struct file *file) __ksym __weak;

/* Shared state with userspace */
int kfunc_get_success = 0;
int kfunc_delete_success = 0;
__u64 kfunc_read_value = 0;
int multi_map_a_ok = 0;
int multi_map_b_ok = 0;
int file_open_success = 0;
__u64 file_open_value = 0;
int file_open_null_path = 0;

/*
 * bdev_alloc_security: kfunc CREATE + DELETE test.
 * The block_device pointer is a direct hook argument.
 */
SEC("?lsm/bdev_alloc_security")
int BPF_PROG(bdev_kfunc_test, struct block_device *bdev)
{
	struct bdev_storage_val *val;
	int ret;

	val = bpf_bdev_storage_get((struct bpf_map *)&bdev_map, bdev,
				    BPF_LOCAL_STORAGE_GET_F_CREATE);
	if (val) {
		val->cookie = 0x0A110C01;
		kfunc_get_success = 1;

		/* Re-lookup to verify persistence */
		val = bpf_bdev_storage_get((struct bpf_map *)&bdev_map, bdev, 0);
		if (val)
			kfunc_read_value = val->cookie;

		ret = bpf_bdev_storage_delete((struct bpf_map *)&bdev_map,
					       bdev);
		if (ret == 0)
			kfunc_delete_success = 1;
	}
	return 0;
}

/*
 * bdev_alloc_security: multi-map test.
 * Creates storage on two maps for the same block device.
 */
SEC("?lsm/bdev_alloc_security")
int BPF_PROG(bdev_multi_map_test, struct block_device *bdev)
{
	struct bdev_storage_val *val_a;
	__u64 *val_b;

	val_a = bpf_bdev_storage_get((struct bpf_map *)&bdev_map, bdev,
				      BPF_LOCAL_STORAGE_GET_F_CREATE);
	if (val_a) {
		val_a->cookie = 0x0A110C02;
		multi_map_a_ok = 1;
	}

	val_b = bpf_bdev_storage_get((struct bpf_map *)&bdev_map_b, bdev,
				      BPF_LOCAL_STORAGE_GET_F_CREATE);
	if (val_b) {
		*val_b = 0x42;
		multi_map_b_ok = 1;
	}

	return 0;
}

/*
 * file_post_open: test bpf_get_file_bdev kfunc.
 *
 * At file_post_open time, f_mapping->host has been remapped to the
 * bdev inode by bdev_open(), so bpf_get_file_bdev() succeeds.
 * Chain: bpf_get_file_bdev -> bpf_bdev_storage_get.
 */
SEC("?lsm/file_post_open")
int BPF_PROG(bdev_file_open_test, struct file *file, int mask)
{
	struct bdev_storage_val *ptr;
	struct block_device *bdev;

	bdev = bpf_get_file_bdev(file);
	if (!bdev)
		return 0;

	ptr = bpf_bdev_storage_get((struct bpf_map *)&bdev_map, bdev,
				    BPF_LOCAL_STORAGE_GET_F_CREATE);
	if (ptr) {
		ptr->cookie = 0x0A110C05;
		file_open_success = 1;
	}

	ptr = bpf_bdev_storage_get((struct bpf_map *)&bdev_map, bdev, 0);
	if (ptr)
		file_open_value = ptr->cookie;

	return 0;
}

/*
 * file_open: verify bpf_get_file_bdev returns NULL before bdev remap.
 *
 * At security_file_open time, f_mapping->host is still the devtmpfs
 * inode.  sb_is_blkdev_sb() returns false, so bpf_get_file_bdev()
 * correctly returns NULL.  This tests the safety guard.
 */
SEC("?lsm/file_open")
int BPF_PROG(bdev_file_open_null_test, struct file *file)
{
	struct block_device *bdev;

	bdev = bpf_get_file_bdev(file);
	if (!bdev)
		file_open_null_path = 1;

	return 0;
}
