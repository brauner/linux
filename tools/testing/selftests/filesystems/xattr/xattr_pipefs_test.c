// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2026 Christian Brauner <brauner@kernel.org>
/*
 * Test extended attributes on pipefs pipes.
 *
 * Anonymous pipes created via pipe2() have their inodes in pipefs, which
 * supports user.* xattrs with per-inode limits: up to 128 xattrs and 128KB
 * total value size. These tests verify xattr operations via fsetxattr/
 * fgetxattr/flistxattr/fremovexattr on a pipe fd, as well as limit enforcement.
 * Both ends of a pipe share one inode, so xattrs set on one end are visible
 * on the other.
 */

#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/xattr.h>
#include <unistd.h>

#include "../../kselftest_harness.h"

#define TEST_XATTR_NAME		"user.testattr"
#define TEST_XATTR_VALUE	"testvalue"
#define TEST_XATTR_VALUE2	"newvalue"

/* Per-inode limits for user.* xattrs on pipefs (from include/linux/xattr.h) */
#define SIMPLE_XATTR_MAX_NR	128
#define SIMPLE_XATTR_MAX_SIZE	(128 << 10)	/* 128 KB */

#ifndef XATTR_SIZE_MAX
#define XATTR_SIZE_MAX 65536
#endif

/*
 * Fixture for pipefs pipe xattr tests.
 * Creates an anonymous pipe; fds[0] is the read end, fds[1] the write end.
 * Both ends share a single pipefs inode. Xattr operations use the write end.
 */
FIXTURE(xattr_pipefs)
{
	int fds[2];
};

FIXTURE_SETUP(xattr_pipefs)
{
	ASSERT_EQ(pipe2(self->fds, 0), 0) {
		TH_LOG("Failed to create pipe: %s", strerror(errno));
	}
}

FIXTURE_TEARDOWN(xattr_pipefs)
{
	if (self->fds[0] >= 0)
		close(self->fds[0]);
	if (self->fds[1] >= 0)
		close(self->fds[1]);
}

TEST_F(xattr_pipefs, set_get_user_xattr)
{
	char buf[256];
	ssize_t ret;

	ret = fsetxattr(self->fds[1], TEST_XATTR_NAME,
			TEST_XATTR_VALUE, strlen(TEST_XATTR_VALUE), 0);
	ASSERT_EQ(ret, 0) {
		TH_LOG("fsetxattr failed: %s", strerror(errno));
	}

	memset(buf, 0, sizeof(buf));
	ret = fgetxattr(self->fds[1], TEST_XATTR_NAME, buf, sizeof(buf));
	ASSERT_EQ(ret, (ssize_t)strlen(TEST_XATTR_VALUE)) {
		TH_LOG("fgetxattr returned %zd: %s", ret, strerror(errno));
	}
	ASSERT_STREQ(buf, TEST_XATTR_VALUE);
}

/*
 * Test that an xattr set on one end of the pipe is visible on the other end,
 * since both file descriptors refer to the same pipefs inode.
 */
TEST_F(xattr_pipefs, shared_across_ends)
{
	char buf[256];
	ssize_t ret;

	/* Set on the write end. */
	ret = fsetxattr(self->fds[1], TEST_XATTR_NAME,
			TEST_XATTR_VALUE, strlen(TEST_XATTR_VALUE), 0);
	ASSERT_EQ(ret, 0) {
		TH_LOG("fsetxattr failed: %s", strerror(errno));
	}

	/* Read it back on the read end. */
	memset(buf, 0, sizeof(buf));
	ret = fgetxattr(self->fds[0], TEST_XATTR_NAME, buf, sizeof(buf));
	ASSERT_EQ(ret, (ssize_t)strlen(TEST_XATTR_VALUE)) {
		TH_LOG("fgetxattr on read end returned %zd: %s",
		       ret, strerror(errno));
	}
	ASSERT_STREQ(buf, TEST_XATTR_VALUE);
}

/*
 * Test listing xattrs on a pipefs pipe.
 * Unlike sockfs there is no synthetic xattr (e.g. system.sockprotoname), so
 * the list contains exactly the user.* xattrs that were set.
 */
TEST_F(xattr_pipefs, list_user_xattr)
{
	char list[4096];
	ssize_t ret;
	char *ptr;
	bool found_user = false;

	ret = fsetxattr(self->fds[1], TEST_XATTR_NAME,
			TEST_XATTR_VALUE, strlen(TEST_XATTR_VALUE), 0);
	ASSERT_EQ(ret, 0) {
		TH_LOG("fsetxattr failed: %s", strerror(errno));
	}

	memset(list, 0, sizeof(list));
	ret = flistxattr(self->fds[1], list, sizeof(list));
	ASSERT_GT(ret, 0) {
		TH_LOG("flistxattr failed: %s", strerror(errno));
	}

	/* Only the single user.* xattr should be present. */
	ASSERT_EQ(ret, (ssize_t)(strlen(TEST_XATTR_NAME) + 1)) {
		TH_LOG("unexpected list size %zd", ret);
	}
	for (ptr = list; ptr < list + ret; ptr += strlen(ptr) + 1) {
		if (strcmp(ptr, TEST_XATTR_NAME) == 0)
			found_user = true;
	}
	ASSERT_TRUE(found_user) {
		TH_LOG("user xattr not found in list");
	}
}

TEST_F(xattr_pipefs, remove_user_xattr)
{
	char buf[256];
	ssize_t ret;

	ret = fsetxattr(self->fds[1], TEST_XATTR_NAME,
			TEST_XATTR_VALUE, strlen(TEST_XATTR_VALUE), 0);
	ASSERT_EQ(ret, 0);

	ret = fremovexattr(self->fds[1], TEST_XATTR_NAME);
	ASSERT_EQ(ret, 0) {
		TH_LOG("fremovexattr failed: %s", strerror(errno));
	}

	ret = fgetxattr(self->fds[1], TEST_XATTR_NAME, buf, sizeof(buf));
	ASSERT_EQ(ret, -1);
	ASSERT_EQ(errno, ENODATA);
}

TEST_F(xattr_pipefs, update_user_xattr)
{
	char buf[256];
	ssize_t ret;

	ret = fsetxattr(self->fds[1], TEST_XATTR_NAME,
			TEST_XATTR_VALUE, strlen(TEST_XATTR_VALUE), 0);
	ASSERT_EQ(ret, 0);

	ret = fsetxattr(self->fds[1], TEST_XATTR_NAME,
			TEST_XATTR_VALUE2, strlen(TEST_XATTR_VALUE2), 0);
	ASSERT_EQ(ret, 0);

	memset(buf, 0, sizeof(buf));
	ret = fgetxattr(self->fds[1], TEST_XATTR_NAME, buf, sizeof(buf));
	ASSERT_EQ(ret, (ssize_t)strlen(TEST_XATTR_VALUE2));
	ASSERT_STREQ(buf, TEST_XATTR_VALUE2);
}

TEST_F(xattr_pipefs, xattr_create_flag)
{
	int ret;

	ret = fsetxattr(self->fds[1], TEST_XATTR_NAME,
			TEST_XATTR_VALUE, strlen(TEST_XATTR_VALUE), 0);
	ASSERT_EQ(ret, 0);

	ret = fsetxattr(self->fds[1], TEST_XATTR_NAME,
			TEST_XATTR_VALUE2, strlen(TEST_XATTR_VALUE2),
			XATTR_CREATE);
	ASSERT_EQ(ret, -1);
	ASSERT_EQ(errno, EEXIST);
}

TEST_F(xattr_pipefs, xattr_replace_flag)
{
	int ret;

	ret = fsetxattr(self->fds[1], TEST_XATTR_NAME,
			TEST_XATTR_VALUE, strlen(TEST_XATTR_VALUE),
			XATTR_REPLACE);
	ASSERT_EQ(ret, -1);
	ASSERT_EQ(errno, ENODATA);
}

TEST_F(xattr_pipefs, get_nonexistent)
{
	char buf[256];
	ssize_t ret;

	ret = fgetxattr(self->fds[1], "user.nonexistent", buf, sizeof(buf));
	ASSERT_EQ(ret, -1);
	ASSERT_EQ(errno, ENODATA);
}

TEST_F(xattr_pipefs, empty_value)
{
	ssize_t ret;

	ret = fsetxattr(self->fds[1], TEST_XATTR_NAME, "", 0, 0);
	ASSERT_EQ(ret, 0);

	ret = fgetxattr(self->fds[1], TEST_XATTR_NAME, NULL, 0);
	ASSERT_EQ(ret, 0);
}

TEST_F(xattr_pipefs, get_size)
{
	ssize_t ret;

	ret = fsetxattr(self->fds[1], TEST_XATTR_NAME,
			TEST_XATTR_VALUE, strlen(TEST_XATTR_VALUE), 0);
	ASSERT_EQ(ret, 0);

	ret = fgetxattr(self->fds[1], TEST_XATTR_NAME, NULL, 0);
	ASSERT_EQ(ret, (ssize_t)strlen(TEST_XATTR_VALUE));
}

TEST_F(xattr_pipefs, buffer_too_small)
{
	char buf[2];
	ssize_t ret;

	ret = fsetxattr(self->fds[1], TEST_XATTR_NAME,
			TEST_XATTR_VALUE, strlen(TEST_XATTR_VALUE), 0);
	ASSERT_EQ(ret, 0);

	ret = fgetxattr(self->fds[1], TEST_XATTR_NAME, buf, sizeof(buf));
	ASSERT_EQ(ret, -1);
	ASSERT_EQ(errno, ERANGE);
}

/*
 * Test that non-user.* namespaces are rejected on a pipe. pipefs installs no
 * trusted.* handler, so the set fails regardless of privilege (EOPNOTSUPP when
 * the trusted.* permission check passes, EPERM otherwise).
 */
TEST_F(xattr_pipefs, reject_trusted)
{
	int ret;

	ret = fsetxattr(self->fds[1], "trusted.foo", "v", 1, 0);
	ASSERT_EQ(ret, -1);
	ASSERT_TRUE(errno == EOPNOTSUPP || errno == EPERM);
}

/*
 * Test maximum number of user.* xattrs per pipe.
 * The kernel enforces SIMPLE_XATTR_MAX_NR (128), so the 129th should
 * fail with ENOSPC.
 */
TEST_F(xattr_pipefs, max_nr_xattrs)
{
	char name[32];
	int i, ret;

	for (i = 0; i < SIMPLE_XATTR_MAX_NR; i++) {
		snprintf(name, sizeof(name), "user.test%03d", i);
		ret = fsetxattr(self->fds[1], name, "v", 1, 0);
		ASSERT_EQ(ret, 0) {
			TH_LOG("fsetxattr %s failed at i=%d: %s",
			       name, i, strerror(errno));
		}
	}

	ret = fsetxattr(self->fds[1], "user.overflow", "v", 1, 0);
	ASSERT_EQ(ret, -1);
	ASSERT_EQ(errno, ENOSPC) {
		TH_LOG("Expected ENOSPC for xattr %d, got %s",
		       SIMPLE_XATTR_MAX_NR + 1, strerror(errno));
	}
}

/*
 * Test maximum total value size for user.* xattrs.
 * The kernel enforces SIMPLE_XATTR_MAX_SIZE (128KB). Individual xattr
 * values are limited to XATTR_SIZE_MAX (64KB) by the VFS, so we need
 * at least two xattrs to hit the total limit.
 */
TEST_F(xattr_pipefs, max_xattr_size)
{
	char *value;
	int ret;

	value = malloc(XATTR_SIZE_MAX);
	ASSERT_NE(value, NULL);
	memset(value, 'A', XATTR_SIZE_MAX);

	/* First 64KB xattr - total = 64KB */
	ret = fsetxattr(self->fds[1], "user.big1", value, XATTR_SIZE_MAX, 0);
	ASSERT_EQ(ret, 0) {
		TH_LOG("first large xattr failed: %s", strerror(errno));
	}

	/* Second 64KB xattr - total = 128KB (exactly at limit) */
	ret = fsetxattr(self->fds[1], "user.big2", value, XATTR_SIZE_MAX, 0);
	free(value);
	ASSERT_EQ(ret, 0) {
		TH_LOG("second large xattr failed: %s", strerror(errno));
	}

	/* Third xattr with 1 byte - total > 128KB, should fail */
	ret = fsetxattr(self->fds[1], "user.big3", "v", 1, 0);
	ASSERT_EQ(ret, -1);
	ASSERT_EQ(errno, ENOSPC) {
		TH_LOG("Expected ENOSPC when exceeding size limit, got %s",
		       strerror(errno));
	}
}

/*
 * Test that removing an xattr frees limit space, allowing re-addition.
 */
TEST_F(xattr_pipefs, limit_remove_readd)
{
	char name[32];
	int i, ret;

	/* Fill up to the maximum count */
	for (i = 0; i < SIMPLE_XATTR_MAX_NR; i++) {
		snprintf(name, sizeof(name), "user.test%03d", i);
		ret = fsetxattr(self->fds[1], name, "v", 1, 0);
		ASSERT_EQ(ret, 0);
	}

	/* Verify we're at the limit */
	ret = fsetxattr(self->fds[1], "user.overflow", "v", 1, 0);
	ASSERT_EQ(ret, -1);
	ASSERT_EQ(errno, ENOSPC);

	/* Remove one xattr */
	ret = fremovexattr(self->fds[1], "user.test000");
	ASSERT_EQ(ret, 0);

	/* Now we should be able to add one more */
	ret = fsetxattr(self->fds[1], "user.newattr", "v", 1, 0);
	ASSERT_EQ(ret, 0) {
		TH_LOG("re-add after remove failed: %s", strerror(errno));
	}
}

/*
 * Test that two different pipes have independent xattrs and limits.
 */
TEST_F(xattr_pipefs, limits_per_inode)
{
	char buf[256];
	int fds2[2];
	ssize_t ret;

	ASSERT_EQ(pipe2(fds2, 0), 0);

	/* Set xattr on first pipe */
	ret = fsetxattr(self->fds[1], TEST_XATTR_NAME,
			TEST_XATTR_VALUE, strlen(TEST_XATTR_VALUE), 0);
	ASSERT_EQ(ret, 0);

	/* First pipe's xattr should not be visible on second pipe */
	ret = fgetxattr(fds2[1], TEST_XATTR_NAME, NULL, 0);
	ASSERT_EQ(ret, -1);
	ASSERT_EQ(errno, ENODATA);

	/* Second pipe should independently accept xattrs */
	ret = fsetxattr(fds2[1], TEST_XATTR_NAME,
			TEST_XATTR_VALUE2, strlen(TEST_XATTR_VALUE2), 0);
	ASSERT_EQ(ret, 0);

	/* Verify each pipe has its own value */
	memset(buf, 0, sizeof(buf));
	ret = fgetxattr(self->fds[1], TEST_XATTR_NAME, buf, sizeof(buf));
	ASSERT_EQ(ret, (ssize_t)strlen(TEST_XATTR_VALUE));
	ASSERT_STREQ(buf, TEST_XATTR_VALUE);

	memset(buf, 0, sizeof(buf));
	ret = fgetxattr(fds2[1], TEST_XATTR_NAME, buf, sizeof(buf));
	ASSERT_EQ(ret, (ssize_t)strlen(TEST_XATTR_VALUE2));
	ASSERT_STREQ(buf, TEST_XATTR_VALUE2);

	close(fds2[0]);
	close(fds2[1]);
}

TEST_HARNESS_MAIN
