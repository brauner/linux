// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2026 Christian Brauner (Amutable) <brauner@kernel.org> */

#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <linux/loop.h>
#include <bpf/btf.h>
#include <test_progs.h>
#include "bdev_ls_lsm.skel.h"
#include "bdev_ls_recursion.skel.h"
#include "bdev_ls_negative.skel.h"
#include "bdev_ls_sleepable.skel.h"
#include "bdev_ls_sleepable_free.skel.h"
#include "bdev_ls_untrusted_free.skel.h"

struct bdev_storage_val {
	__u64 cookie;
};

/*
 * Create a loop device backed by a temporary file.
 * Returns the fd to /dev/loopN on success, -1 on failure.
 * The loop device number is stored in *loop_num_out.
 *
 * Uses LOOP_CTL_GET_FREE to find an available number, then
 * LOOP_CTL_REMOVE + LOOP_CTL_ADD to force allocation of a brand-new
 * block_device so that bdev_alloc_security fires.  Without this,
 * GET_FREE returns an existing unbound device whose block_device was
 * allocated at boot and bdev_alloc_security would not fire again.
 */
static int create_loop_device(int *loop_num_out)
{
	char loop_path[64];
	int ctrl_fd, loop_fd, backing_fd;
	int loop_num;
	char template[] = "/tmp/bdev_test_XXXXXX";

	ctrl_fd = open("/dev/loop-control", O_RDWR);
	if (ctrl_fd < 0)
		return -1;

	loop_num = ioctl(ctrl_fd, LOOP_CTL_GET_FREE);
	if (loop_num < 0) {
		close(ctrl_fd);
		return -1;
	}

	/*
	 * Remove the existing (pre-allocated) device and re-add it to
	 * force a fresh block_device allocation.
	 */
	ioctl(ctrl_fd, LOOP_CTL_REMOVE, loop_num);
	if (ioctl(ctrl_fd, LOOP_CTL_ADD, loop_num) < 0) {
		close(ctrl_fd);
		return -1;
	}
	close(ctrl_fd);

	backing_fd = mkstemp(template);
	if (backing_fd < 0)
		return -1;

	/* Extend backing file to 1 MiB so the loop device has a size */
	if (ftruncate(backing_fd, 1024 * 1024)) {
		close(backing_fd);
		unlink(template);
		return -1;
	}

	snprintf(loop_path, sizeof(loop_path), "/dev/loop%d", loop_num);
	loop_fd = open(loop_path, O_RDWR);
	if (loop_fd < 0) {
		close(backing_fd);
		unlink(template);
		return -1;
	}

	if (ioctl(loop_fd, LOOP_SET_FD, backing_fd)) {
		close(loop_fd);
		close(backing_fd);
		unlink(template);
		return -1;
	}

	close(backing_fd);
	unlink(template);

	*loop_num_out = loop_num;
	return loop_fd;
}

/*
 * Detach the backing file from the loop device, remove the device,
 * and close the fd.
 */
static void destroy_loop_device(int loop_fd, int loop_num)
{
	int ctrl_fd;

	ioctl(loop_fd, LOOP_CLR_FD, 0);
	close(loop_fd);
	ctrl_fd = open("/dev/loop-control", O_RDWR);
	if (ctrl_fd >= 0) {
		ioctl(ctrl_fd, LOOP_CTL_REMOVE, loop_num);
		close(ctrl_fd);
	}
}

/* Userspace CRUD via bpf_map_*_elem() */
static void test_syscall_crud(void)
{
	struct bdev_storage_val val = {}, lookup = {};
	int loop_fd, loop_num, next;
	struct bdev_ls_lsm *skel;
	int map_fd, err;
	int bad_fd, null_fd;

	skel = bdev_ls_lsm__open_and_load();
	if (!ASSERT_OK_PTR(skel, "open_and_load"))
		return;
	map_fd = bpf_map__fd(skel->maps.bdev_map);

	loop_fd = create_loop_device(&loop_num);
	if (!ASSERT_GE(loop_fd, 0, "create_loop_device"))
		goto destroy;

	/* CREATE */
	val.cookie = 0x0A110C01;
	err = bpf_map_update_elem(map_fd, &loop_fd, &val, BPF_ANY);
	ASSERT_OK(err, "update_create");

	/* LOOKUP */
	err = bpf_map_lookup_elem(map_fd, &loop_fd, &lookup);
	ASSERT_OK(err, "lookup");
	ASSERT_EQ(lookup.cookie, 0x0A110C01, "lookup_value");

	/* UPDATE existing */
	val.cookie = 0x0A110C02;
	err = bpf_map_update_elem(map_fd, &loop_fd, &val, BPF_EXIST);
	ASSERT_OK(err, "update_exist");
	err = bpf_map_lookup_elem(map_fd, &loop_fd, &lookup);
	ASSERT_OK(err, "lookup_after_update");
	ASSERT_EQ(lookup.cookie, 0x0A110C02, "updated_value");

	/* DELETE */
	err = bpf_map_delete_elem(map_fd, &loop_fd);
	ASSERT_OK(err, "delete");

	/* LOOKUP after DELETE -> ENOENT */
	err = bpf_map_lookup_elem(map_fd, &loop_fd, &lookup);
	ASSERT_ERR(err, "lookup_after_delete");

	/* Double DELETE -> ENOENT */
	err = bpf_map_delete_elem(map_fd, &loop_fd);
	ASSERT_ERR(err, "double_delete");

	/* Bad fd (-1) -> EBADF */
	bad_fd = -1;
	err = bpf_map_lookup_elem(map_fd, &bad_fd, &lookup);
	ASSERT_ERR(err, "lookup_bad_fd");

	/* Non-bdev fd (char device /dev/null) -> EBADF */
	null_fd = open("/dev/null", O_RDONLY);
	if (ASSERT_GE(null_fd, 0, "open_dev_null")) {
		err = bpf_map_lookup_elem(map_fd, &null_fd, &lookup);
		ASSERT_ERR(err, "lookup_non_bdev_fd");
		close(null_fd);
	}

	/* GET_NEXT_KEY -> ENOTSUPP */
	err = bpf_map_get_next_key(map_fd, &loop_fd, &next);
	ASSERT_ERR(err, "get_next_key");

	destroy_loop_device(loop_fd, loop_num);
destroy:
	bdev_ls_lsm__destroy(skel);
}

/* Map creation parameter validation */
static void test_map_create_checks(void)
{
	LIBBPF_OPTS(bpf_map_create_opts, opts);
	struct btf *btf;
	int btf_fd, key_id, val_id;
	int fd;

	btf = btf__new_empty();
	if (!ASSERT_OK_PTR(btf, "btf_new"))
		return;
	key_id = btf__add_int(btf, "int", 4, BTF_INT_SIGNED);
	val_id = btf__add_int(btf, "__u64", 8, 0);
	if (!ASSERT_GT(key_id, 0, "add_key_type") ||
	    !ASSERT_GT(val_id, 0, "add_val_type"))
		goto free_btf;

	if (!ASSERT_OK(btf__load_into_kernel(btf), "btf_load"))
		goto free_btf;
	btf_fd = btf__fd(btf);

	/* All tests use these valid BTF IDs so only the intended bad param triggers EINVAL */
	opts.btf_fd = btf_fd;
	opts.btf_key_type_id = key_id;
	opts.btf_value_type_id = val_id;

	/* Missing BPF_F_NO_PREALLOC -> EINVAL */
	opts.map_flags = 0;
	fd = bpf_map_create(BPF_MAP_TYPE_BDEV_STORAGE, "bad1",
			    sizeof(int), sizeof(__u64), 0, &opts);
	if (!ASSERT_LT(fd, 0, "no_prealloc"))
		close(fd);

	/* Non-zero max_entries -> EINVAL */
	opts.map_flags = BPF_F_NO_PREALLOC;
	fd = bpf_map_create(BPF_MAP_TYPE_BDEV_STORAGE, "bad2",
			    sizeof(int), sizeof(__u64), 1, &opts);
	if (!ASSERT_LT(fd, 0, "nonzero_max_entries"))
		close(fd);

	/* Zero value_size -> EINVAL */
	fd = bpf_map_create(BPF_MAP_TYPE_BDEV_STORAGE, "bad3",
			    sizeof(int), 0, 0, &opts);
	if (!ASSERT_LT(fd, 0, "zero_value_size"))
		close(fd);

	/* Invalid flags -> EINVAL */
	opts.map_flags = BPF_F_NO_PREALLOC | BPF_F_RDONLY_PROG;
	fd = bpf_map_create(BPF_MAP_TYPE_BDEV_STORAGE, "bad4",
			    sizeof(int), sizeof(__u64), 0, &opts);
	if (!ASSERT_LT(fd, 0, "invalid_flags"))
		close(fd);

free_btf:
	btf__free(btf);
}

/* BPF-side kfunc GET and DELETE */
static void test_lsm_kfunc(void)
{
	struct bdev_ls_lsm *skel;
	int err, loop_fd, loop_num;

	skel = bdev_ls_lsm__open();
	if (!ASSERT_OK_PTR(skel, "open"))
		return;

	bpf_program__set_autoload(skel->progs.bdev_kfunc_test, true);

	err = bdev_ls_lsm__load(skel);
	if (!ASSERT_OK(err, "load"))
		goto out;

	err = bdev_ls_lsm__attach(skel);
	if (!ASSERT_OK(err, "attach"))
		goto out;

	/* Creating the loop device triggers bdev_alloc_security */
	loop_fd = create_loop_device(&loop_num);
	if (!ASSERT_GE(loop_fd, 0, "create_loop_device"))
		goto out;

	ASSERT_EQ(skel->bss->kfunc_get_success, 1, "get_success");
	ASSERT_EQ(skel->bss->kfunc_read_value, 0x0A110C01, "read_value");
	ASSERT_EQ(skel->bss->kfunc_delete_success, 1, "delete_success");

	destroy_loop_device(loop_fd, loop_num);
out:
	bdev_ls_lsm__destroy(skel);
}

/* Multiple maps on the same block device */
static void test_multi_map(void)
{
	struct bdev_storage_val lookup_a = {};
	struct bdev_ls_lsm *skel;
	int map_a_fd, map_b_fd, err;
	int loop_fd, loop_num;
	__u64 lookup_b = 0;

	skel = bdev_ls_lsm__open();
	if (!ASSERT_OK_PTR(skel, "open"))
		return;

	bpf_program__set_autoload(skel->progs.bdev_multi_map_test, true);

	err = bdev_ls_lsm__load(skel);
	if (!ASSERT_OK(err, "load"))
		goto out;

	err = bdev_ls_lsm__attach(skel);
	if (!ASSERT_OK(err, "attach"))
		goto out;

	/* Creating the loop device triggers bdev_alloc_security */
	loop_fd = create_loop_device(&loop_num);
	if (!ASSERT_GE(loop_fd, 0, "create_loop_device"))
		goto out;

	ASSERT_EQ(skel->bss->multi_map_a_ok, 1, "map_a_created");
	ASSERT_EQ(skel->bss->multi_map_b_ok, 1, "map_b_created");

	/* Verify from userspace using the loop device fd as key */
	map_a_fd = bpf_map__fd(skel->maps.bdev_map);
	map_b_fd = bpf_map__fd(skel->maps.bdev_map_b);

	err = bpf_map_lookup_elem(map_a_fd, &loop_fd, &lookup_a);
	ASSERT_OK(err, "lookup_map_a");
	ASSERT_EQ(lookup_a.cookie, 0x0A110C02, "map_a_value");

	err = bpf_map_lookup_elem(map_b_fd, &loop_fd, &lookup_b);
	ASSERT_OK(err, "lookup_map_b");
	ASSERT_EQ(lookup_b, 0x42, "map_b_value");

	destroy_loop_device(loop_fd, loop_num);
out:
	bdev_ls_lsm__destroy(skel);
}

/* Storage is cleaned up when block device is destroyed */
static void test_cleanup_on_bdev_destroy(void)
{
	struct bdev_storage_val val = { .cookie = 0x0A110C04 };
	struct bdev_storage_val lookup = {};
	struct bdev_ls_lsm *skel;
	char loop_path[64];
	int map_fd, err;
	int loop_fd, loop_num;
	int new_loop_fd;

	loop_fd = create_loop_device(&loop_num);
	if (!ASSERT_GE(loop_fd, 0, "create_loop_device"))
		return;

	skel = bdev_ls_lsm__open_and_load();
	if (!ASSERT_OK_PTR(skel, "open_and_load"))
		goto cleanup_loop;

	map_fd = bpf_map__fd(skel->maps.bdev_map);

	err = bpf_map_update_elem(map_fd, &loop_fd, &val, BPF_ANY);
	if (!ASSERT_OK(err, "update_elem"))
		goto out;

	err = bpf_map_lookup_elem(map_fd, &loop_fd, &lookup);
	ASSERT_OK(err, "lookup_while_alive");
	ASSERT_EQ(lookup.cookie, 0x0A110C04, "cookie_alive");

	ioctl(loop_fd, LOOP_CLR_FD, 0);
	close(loop_fd);
	loop_fd = -1;

	/* Retry: udevd may briefly hold the device open. */
	{
		int ctrl_fd, retries;

		ctrl_fd = open("/dev/loop-control", O_RDWR);
		if (!ASSERT_GE(ctrl_fd, 0, "open_loop_control"))
			goto out;

		for (retries = 0; retries < 10; retries++) {
			err = ioctl(ctrl_fd, LOOP_CTL_REMOVE, loop_num);
			if (err == 0)
				break;
			usleep(100 * 1000); /* 100 ms */
		}
		if (!ASSERT_OK(err, "loop_ctl_remove")) {
			close(ctrl_fd);
			goto out;
		}
		close(ctrl_fd);
	}

	/* Flush inode cache and wait for RCU callback (bdev_free_inode). */
	{
		int drop_fd = open("/proc/sys/vm/drop_caches", O_WRONLY);

		if (drop_fd >= 0) {
			write(drop_fd, "3", 1);
			close(drop_fd);
		}
	}
	kern_sync_rcu();
	kern_sync_rcu();
	kern_sync_rcu();

	/* Re-add loop device; fresh block_device must have no storage. */
	{
		int ctrl_fd;

		ctrl_fd = open("/dev/loop-control", O_RDWR);
		if (!ASSERT_GE(ctrl_fd, 0, "open_loop_control_readd"))
			goto out;

		err = ioctl(ctrl_fd, LOOP_CTL_ADD, loop_num);
		close(ctrl_fd);
		if (!ASSERT_OK(err, "loop_ctl_readd"))
			goto out;
	}

	snprintf(loop_path, sizeof(loop_path), "/dev/loop%d", loop_num);
	new_loop_fd = open(loop_path, O_RDWR);
	if (!ASSERT_GE(new_loop_fd, 0, "open_new_loop"))
		goto out;

	err = bpf_map_lookup_elem(map_fd, &new_loop_fd, &lookup);
	ASSERT_ERR(err, "lookup_after_destroy");

	close(new_loop_fd);

	{
		int ctrl_fd;

		ctrl_fd = open("/dev/loop-control", O_RDWR);
		if (ctrl_fd >= 0) {
			ioctl(ctrl_fd, LOOP_CTL_REMOVE, loop_num);
			close(ctrl_fd);
		}
	}

	goto out;

cleanup_loop:
	if (loop_fd >= 0)
		destroy_loop_device(loop_fd, loop_num);
	return;

out:
	bdev_ls_lsm__destroy(skel);
}

/* Per-CPU busy counter with sequential calls */
static void test_recursion(void)
{
	struct bdev_ls_recursion *skel;
	int err, loop_fd, loop_num;

	skel = bdev_ls_recursion__open_and_load();
	if (!ASSERT_OK_PTR(skel, "open_and_load"))
		return;

	err = bdev_ls_recursion__attach(skel);
	if (!ASSERT_OK(err, "attach"))
		goto out;

	/* Creating the loop device triggers bdev_alloc_security */
	loop_fd = create_loop_device(&loop_num);
	if (!ASSERT_GE(loop_fd, 0, "create_loop_device"))
		goto out;

	ASSERT_EQ(skel->bss->map_a_ok, 1, "map_a_created");
	ASSERT_EQ(skel->bss->delete_ok, 1, "delete_succeeded");
	ASSERT_EQ(skel->bss->recreate_ok, 1, "recreate_after_delete");
	ASSERT_EQ(skel->bss->map_b_ok, 1, "map_b_created");

	destroy_loop_device(loop_fd, loop_num);
out:
	bdev_ls_recursion__destroy(skel);
}

/* Verifier rejects wrong program type */
static void test_negative(void)
{
	struct bdev_ls_negative *skel;

	skel = bdev_ls_negative__open_and_load();
	if (!ASSERT_ERR_PTR(skel, "open_and_load")) {
		bdev_ls_negative__destroy(skel);
		return;
	}
}

/* Sleepable LSM program with BDEV_STORAGE */
static void test_sleepable(void)
{
	struct bdev_ls_sleepable *skel;
	int err, loop_fd, loop_num;

	skel = bdev_ls_sleepable__open();
	if (!ASSERT_OK_PTR(skel, "open"))
		return;

	bpf_program__set_autoload(skel->progs.sleepable_bdev_storage, true);

	err = bdev_ls_sleepable__load(skel);
	if (!ASSERT_OK(err, "load"))
		goto out;

	err = bdev_ls_sleepable__attach(skel);
	if (!ASSERT_OK(err, "attach"))
		goto out;

	/* Creating the loop device triggers bdev_alloc_security */
	loop_fd = create_loop_device(&loop_num);
	if (!ASSERT_GE(loop_fd, 0, "create_loop_device"))
		goto out;

	ASSERT_EQ(skel->bss->get_success, 1, "sleepable_get");
	ASSERT_EQ(skel->bss->read_value, 0x0A110C03, "sleepable_value");

	destroy_loop_device(loop_fd, loop_num);
out:
	bdev_ls_sleepable__destroy(skel);
}

/*
 * bpf_get_file_bdev from file_post_open hook.
 *
 * At file_post_open time, bdev_open() has already remapped
 * f_mapping->host to the bdev inode, so bpf_get_file_bdev()
 * returns a valid block_device pointer.
 */
static void test_file_open(void)
{
	struct bdev_storage_val lookup = {};
	struct bdev_ls_lsm *skel;
	char loop_path[64];
	int err, loop_fd, loop_num;
	int reopen_fd, map_fd;

	loop_fd = create_loop_device(&loop_num);
	if (!ASSERT_GE(loop_fd, 0, "create_loop_device"))
		return;

	skel = bdev_ls_lsm__open();
	if (!ASSERT_OK_PTR(skel, "open"))
		goto cleanup_loop;

	bpf_program__set_autoload(skel->progs.bdev_file_open_test, true);

	err = bdev_ls_lsm__load(skel);
	if (!ASSERT_OK(err, "load"))
		goto out;

	err = bdev_ls_lsm__attach(skel);
	if (!ASSERT_OK(err, "attach"))
		goto out;

	/*
	 * Re-open the loop device to trigger file_post_open.
	 * The BPF program fires during this open() call.
	 */
	snprintf(loop_path, sizeof(loop_path), "/dev/loop%d", loop_num);
	reopen_fd = open(loop_path, O_RDONLY);
	if (!ASSERT_GE(reopen_fd, 0, "reopen_loop"))
		goto out;

	ASSERT_EQ(skel->bss->file_open_success, 1, "file_open_success");
	ASSERT_EQ(skel->bss->file_open_value, 0x0A110C05, "file_open_value");

	/* Verify from userspace using the reopened fd as key */
	map_fd = bpf_map__fd(skel->maps.bdev_map);
	err = bpf_map_lookup_elem(map_fd, &reopen_fd, &lookup);
	ASSERT_OK(err, "lookup_from_userspace");
	ASSERT_EQ(lookup.cookie, 0x0A110C05, "userspace_value");

	close(reopen_fd);
out:
	bdev_ls_lsm__destroy(skel);
cleanup_loop:
	destroy_loop_device(loop_fd, loop_num);
}

/*
 * bpf_get_file_bdev returns NULL at file_open time.
 *
 * At security_file_open time, f_mapping->host is still the devtmpfs
 * inode (bdev_open() hasn't remapped it yet).  sb_is_blkdev_sb()
 * returns false, so bpf_get_file_bdev() returns NULL.
 */
static void test_file_open_null(void)
{
	struct bdev_ls_lsm *skel;
	char loop_path[64];
	int err, loop_fd, loop_num;
	int reopen_fd;

	loop_fd = create_loop_device(&loop_num);
	if (!ASSERT_GE(loop_fd, 0, "create_loop_device"))
		return;

	skel = bdev_ls_lsm__open();
	if (!ASSERT_OK_PTR(skel, "open"))
		goto cleanup_loop;

	bpf_program__set_autoload(skel->progs.bdev_file_open_null_test, true);

	err = bdev_ls_lsm__load(skel);
	if (!ASSERT_OK(err, "load"))
		goto out;

	err = bdev_ls_lsm__attach(skel);
	if (!ASSERT_OK(err, "attach"))
		goto out;

	/* Re-open the loop device to trigger file_open */
	snprintf(loop_path, sizeof(loop_path), "/dev/loop%d", loop_num);
	reopen_fd = open(loop_path, O_RDONLY);
	if (!ASSERT_GE(reopen_fd, 0, "reopen_loop"))
		goto out;

	/*
	 * bpf_get_file_bdev returned NULL at file_open time because
	 * f_mapping->host was still the devtmpfs inode.
	 */
	ASSERT_EQ(skel->bss->file_open_null_path, 1, "null_path_taken");

	close(reopen_fd);
out:
	bdev_ls_lsm__destroy(skel);
cleanup_loop:
	destroy_loop_device(loop_fd, loop_num);
}

/* Verifier rejects sleepable bdev_free_security */
static void test_negative_sleepable_free(void)
{
	struct bdev_ls_sleepable_free *skel;

	skel = bdev_ls_sleepable_free__open_and_load();
	if (!ASSERT_ERR_PTR(skel, "open_and_load")) {
		bdev_ls_sleepable_free__destroy(skel);
		return;
	}
}

/* Verifier rejects KF_RCU kfuncs from untrusted bdev_free_security */
static void test_negative_untrusted_free(void)
{
	struct bdev_ls_untrusted_free *skel;

	skel = bdev_ls_untrusted_free__open_and_load();
	if (!ASSERT_ERR_PTR(skel, "open_and_load")) {
		bdev_ls_untrusted_free__destroy(skel);
		return;
	}
}

void test_bdev_local_storage(void)
{
	if (test__start_subtest("syscall_crud"))
		test_syscall_crud();
	if (test__start_subtest("map_create_checks"))
		test_map_create_checks();
	if (test__start_subtest("lsm_kfunc"))
		test_lsm_kfunc();
	if (test__start_subtest("multi_map"))
		test_multi_map();
	if (test__start_subtest("cleanup_on_bdev_destroy"))
		test_cleanup_on_bdev_destroy();
	if (test__start_subtest("recursion"))
		test_recursion();
	if (test__start_subtest("negative"))
		test_negative();
	if (test__start_subtest("sleepable"))
		test_sleepable();
	if (test__start_subtest("file_open"))
		test_file_open();
	if (test__start_subtest("file_open_null"))
		test_file_open_null();
	if (test__start_subtest("negative_sleepable_free"))
		test_negative_sleepable_free();
	if (test__start_subtest("negative_untrusted_free"))
		test_negative_untrusted_free();
}
