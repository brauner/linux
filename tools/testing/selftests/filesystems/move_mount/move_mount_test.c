// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (c) 2026 Christian Brauner <brauner@kernel.org>

#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <sched.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/mount.h>
#include <sys/wait.h>
#include <unistd.h>
#include <sys/syscall.h>

#include "../wrappers.h"
#include "../utils.h"
#include "../statmount/statmount.h"
#include "../../kselftest_harness.h"

#include <linux/stat.h>

#ifndef MOVE_MOUNT_BENEATH
#define MOVE_MOUNT_BENEATH 0x00000200
#endif

#ifndef MOVE_MOUNT_SET_GROUP
#define MOVE_MOUNT_SET_GROUP 0x00000100
#endif

#ifndef MOVE_MOUNT_PIVOT_ROOT
#define MOVE_MOUNT_PIVOT_ROOT 0x00000400
#endif

static uint64_t get_unique_mnt_id_fd(int fd)
{
	struct statx sx;
	int ret;

	ret = statx(fd, "", AT_EMPTY_PATH, STATX_MNT_ID_UNIQUE, &sx);
	if (ret == -1)
		return 0;

	if (!(sx.stx_mask & STATX_MNT_ID_UNIQUE))
		return 0;

	return sx.stx_mnt_id;
}

FIXTURE(move_mount) {
	uint64_t orig_root_id;
};

FIXTURE_SETUP(move_mount)
{
	ASSERT_EQ(unshare(CLONE_NEWNS), 0);

	ASSERT_EQ(mount("", "/", NULL, MS_REC | MS_PRIVATE, NULL), 0);

	self->orig_root_id = get_unique_mnt_id("/");
	ASSERT_NE(self->orig_root_id, 0);
}

FIXTURE_TEARDOWN(move_mount)
{
}

/*
 * Test that MOVE_MOUNT_PIVOT_ROOT without MOVE_MOUNT_BENEATH fails.
 * The kernel requires both flags to be set together.
 */
TEST_F(move_mount, pivot_root_requires_beneath)
{
	int fd_tree, ret;

	/* Create a new mount that we'll try to pivot to */
	fd_tree = sys_open_tree(AT_FDCWD, "/",
				OPEN_TREE_CLONE | OPEN_TREE_CLOEXEC);
	ASSERT_GE(fd_tree, 0);

	/* Try MOVE_MOUNT_PIVOT_ROOT without MOVE_MOUNT_BENEATH - should fail */
	ret = sys_move_mount(fd_tree, "", AT_FDCWD, "/",
			     MOVE_MOUNT_F_EMPTY_PATH | MOVE_MOUNT_PIVOT_ROOT);
	ASSERT_EQ(ret, -1);
	ASSERT_EQ(errno, EINVAL);

	close(fd_tree);
}

/*
 * Test that MOVE_MOUNT_PIVOT_ROOT with MOVE_MOUNT_SET_GROUP fails.
 * These two flags are mutually exclusive.
 */
TEST_F(move_mount, pivot_root_and_set_group_exclusive)
{
	int fd_tree, ret;

	fd_tree = sys_open_tree(AT_FDCWD, "/",
				OPEN_TREE_CLONE | OPEN_TREE_CLOEXEC);
	ASSERT_GE(fd_tree, 0);

	/* Try both MOVE_MOUNT_PIVOT_ROOT and MOVE_MOUNT_SET_GROUP - should fail */
	ret = sys_move_mount(fd_tree, "", AT_FDCWD, "/",
			     MOVE_MOUNT_F_EMPTY_PATH | MOVE_MOUNT_BENEATH |
			     MOVE_MOUNT_PIVOT_ROOT | MOVE_MOUNT_SET_GROUP);
	ASSERT_EQ(ret, -1);
	ASSERT_EQ(errno, EINVAL);

	close(fd_tree);
}

/*
 * Test that MOVE_MOUNT_PIVOT_ROOT on a non-root target fails.
 * The target must be the caller's current root mount.
 */
TEST_F(move_mount, pivot_root_target_must_be_root)
{
	int fd_tree, ret;

	/* Create a subdirectory for testing */
	ASSERT_EQ(mkdir("/subdir", 0755), 0);

	/* Mount something on the subdirectory */
	ASSERT_EQ(mount("tmpfs", "/subdir", "tmpfs", 0, NULL), 0);

	fd_tree = sys_open_tree(AT_FDCWD, "/",
				OPEN_TREE_CLONE | OPEN_TREE_CLOEXEC);
	ASSERT_GE(fd_tree, 0);

	/*
	 * Try MOVE_MOUNT_PIVOT_ROOT targeting /subdir instead of / - should fail
	 * because the target is not the root mount.
	 */
	ret = sys_move_mount(fd_tree, "", AT_FDCWD, "/subdir",
			     MOVE_MOUNT_F_EMPTY_PATH | MOVE_MOUNT_BENEATH |
			     MOVE_MOUNT_PIVOT_ROOT);
	ASSERT_EQ(ret, -1);
	ASSERT_EQ(errno, EINVAL);

	close(fd_tree);

	/* Cleanup */
	umount("/subdir");
	rmdir("/subdir");
}

/*
 * Test successful MOVE_MOUNT_PIVOT_ROOT operation.
 * This mounts a new filesystem beneath the root and pivots to it,
 * equivalent to chdir(new_rootfs); pivot_root(".", ".")
 */
TEST_F(move_mount, pivot_root_success)
{
	int fd_tree, ret;
	uint64_t clone_id, root_id_after_pivot;
	struct statmount sm;

	/* Create a new mount tree */
	fd_tree = sys_open_tree(AT_FDCWD, "/",
				OPEN_TREE_CLONE | OPEN_TREE_CLOEXEC);
	ASSERT_GE(fd_tree, 0);

	/* Get the mount ID of the detached clone */
	clone_id = get_unique_mnt_id_fd(fd_tree);
	ASSERT_NE(clone_id, 0);
	ASSERT_NE(clone_id, self->orig_root_id);

	ASSERT_EQ(fchdir(fd_tree), 0);

	/*
	 * Use MOVE_MOUNT_BENEATH | MOVE_MOUNT_PIVOT_ROOT to:
	 * 1. Mount the new tree beneath the current root
	 * 2. Pivot the root to the new tree
	 * 3. Old root ends up stacked on top of "."
	 */
	ret = sys_move_mount(fd_tree, "", AT_FDCWD, "/",
			     MOVE_MOUNT_F_EMPTY_PATH | MOVE_MOUNT_BENEATH |
			     MOVE_MOUNT_PIVOT_ROOT);
	ASSERT_EQ(ret, 0);

	close(fd_tree);

	root_id_after_pivot = get_unique_mnt_id("/");
	ASSERT_NE(root_id_after_pivot, 0);
	ASSERT_EQ(root_id_after_pivot, clone_id);

	ASSERT_EQ(statmount(self->orig_root_id, 0, STATMOUNT_MNT_BASIC, &sm, sizeof(sm), 0), 0);
	ASSERT_EQ(sm.mnt_parent_id, clone_id);

	ASSERT_EQ(umount2(".", MNT_DETACH), 0);
}

/*
 * Test MOVE_MOUNT_PIVOT_ROOT in a child process to verify
 * process-specific root changes.
 */
TEST_F(move_mount, pivot_root_child_process)
{
	int fd_tree;
	uint64_t clone_id;
	pid_t pid;
	int status;

	fd_tree = sys_open_tree(AT_FDCWD, "/",
				OPEN_TREE_CLONE | OPEN_TREE_CLOEXEC);
	ASSERT_GE(fd_tree, 0);

	/* Get the mount ID of the detached clone */
	clone_id = get_unique_mnt_id_fd(fd_tree);
	ASSERT_NE(clone_id, 0);

	pid = fork();
	ASSERT_GE(pid, 0);

	if (pid == 0) {
		int ret;
		uint64_t root_id_after_pivot;
		struct statmount sm;

		if (fchdir(fd_tree))
			_exit(1);

		/* Perform pivot root in child */
		ret = sys_move_mount(fd_tree, "", AT_FDCWD, "/",
				     MOVE_MOUNT_F_EMPTY_PATH | MOVE_MOUNT_BENEATH |
				     MOVE_MOUNT_PIVOT_ROOT);
		if (ret != 0)
			_exit(2);

		root_id_after_pivot = get_unique_mnt_id("/");
		if (root_id_after_pivot != clone_id)
			_exit(3);

		if (statmount(self->orig_root_id, 0, STATMOUNT_MNT_BASIC, &sm, sizeof(sm), 0))
			_exit(4);

		if (sm.mnt_parent_id != clone_id)
			_exit(5);

		if (umount2(".", MNT_DETACH))
			_exit(6);

		_exit(0);
	}

	close(fd_tree);

	ASSERT_EQ(waitpid(pid, &status, 0), pid);
	ASSERT_TRUE(WIFEXITED(status));
	ASSERT_EQ(WEXITSTATUS(status), 0);
}

/*
 * Test that MOVE_MOUNT_PIVOT_ROOT correctly changes the root and stacks
 * the old root on top. This is equivalent to chdir(new_rootfs); pivot_root(".", ".")
 * After pivot:
 * - The process root points to the new mount (clone)
 * - The old root is stacked on top at "."
 * - Accessing "." shows the old root (topmost mount)
 * - Unmounting "." via MNT_DETACH reveals the new root underneath
 */
TEST_F(move_mount, pivot_root_old_root_accessible)
{
	int fd_tree, ret;
	uint64_t clone_id, root_id_after_pivot;
	struct statmount sm;

	/*
	 * Clone the root. This creates a new mount with a different mount ID
	 * that will become the new root after pivot.
	 */
	fd_tree = sys_open_tree(AT_FDCWD, "/",
				OPEN_TREE_CLONE | OPEN_TREE_CLOEXEC);
	ASSERT_GE(fd_tree, 0);

	/* Get the mount ID of the detached clone */
	clone_id = get_unique_mnt_id_fd(fd_tree);
	ASSERT_NE(clone_id, 0);
	ASSERT_NE(clone_id, self->orig_root_id);

	ASSERT_EQ(fchdir(fd_tree), 0);

	/*
	 * Mount the clone beneath the current root and pivot to it.
	 */
	ret = sys_move_mount(fd_tree, "", AT_FDCWD, "/",
			     MOVE_MOUNT_F_EMPTY_PATH | MOVE_MOUNT_BENEATH |
			     MOVE_MOUNT_PIVOT_ROOT);
	ASSERT_EQ(ret, 0);

	close(fd_tree);

	/*
	 * Now "." should show the cloned mount's ID (the new root).
	 */
	root_id_after_pivot = get_unique_mnt_id(".");
	ASSERT_NE(root_id_after_pivot, 0);
	ASSERT_EQ(root_id_after_pivot, clone_id);

	ASSERT_EQ(statmount(self->orig_root_id, 0, STATMOUNT_MNT_BASIC, &sm, sizeof(sm), 0), 0);
	ASSERT_EQ(sm.mnt_parent_id, clone_id);

	/*
	 * Unmount the old root (which is on top) using MNT_DETACH.
	 * This reveals the new root underneath.
	 */
	ret = umount2(".", MNT_DETACH);
	ASSERT_EQ(ret, 0);
}

/*
 * Test that MOVE_MOUNT_BENEATH without MOVE_MOUNT_PIVOT_ROOT on root fails.
 * Mounting beneath the rootfs only makes sense when MNT_TREE_PIVOT_ROOT is used.
 */
TEST_F(move_mount, beneath_root_requires_pivot_root)
{
	int fd_tree, ret;

	fd_tree = sys_open_tree(AT_FDCWD, "/",
				OPEN_TREE_CLONE | OPEN_TREE_CLOEXEC);
	ASSERT_GE(fd_tree, 0);

	/*
	 * Try MOVE_MOUNT_BENEATH on root without MOVE_MOUNT_PIVOT_ROOT.
	 * This should fail because mounting beneath root doesn't make
	 * sense without also pivoting to the new root.
	 */
	ret = sys_move_mount(fd_tree, "", AT_FDCWD, "/",
			     MOVE_MOUNT_F_EMPTY_PATH | MOVE_MOUNT_BENEATH);
	ASSERT_EQ(ret, -1);
	ASSERT_EQ(errno, EINVAL);

	close(fd_tree);
}

TEST_HARNESS_MAIN
