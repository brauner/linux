// SPDX-License-Identifier: GPL-2.0
/*
 * An unmounted mount tree that a file descriptor keeps alive can neither be
 * copied nor have its propagation changed: its mounts are put and vacated
 * behind the root's back, so nothing may walk it under namespace_sem.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>
#include <linux/mount.h>

#include "../wrappers.h"
#include "../../kselftest_harness.h"

#ifndef __NR_mount_setattr
#define __NR_mount_setattr 442
#endif

#ifndef __NR_pidfd_open
#define __NR_pidfd_open 434
#endif

#define PATH_LEN	64

static inline int sys_mount_setattr(int dfd, const char *path, unsigned int flags,
				    struct mount_attr *attr, size_t size)
{
	return syscall(__NR_mount_setattr, dfd, path, flags, attr, size);
}

static inline int sys_pidfd_open(pid_t pid, unsigned int flags)
{
	return syscall(__NR_pidfd_open, pid, flags);
}

static int write_file(const char *path, const char *s)
{
	ssize_t n = -1;
	int fd;

	fd = open(path, O_WRONLY | O_CLOEXEC);
	if (fd >= 0) {
		n = write(fd, s, strlen(s));
		close(fd);
	}
	return n == (ssize_t)strlen(s) ? 0 : -1;
}

static int touch(const char *path)
{
	int fd;

	fd = open(path, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0644);
	if (fd < 0)
		return -1;
	close(fd);
	return 0;
}

/* Become root in a new user namespace with a private mount namespace. */
static int enter_userns(void)
{
	uid_t uid = getuid();
	gid_t gid = getgid();
	char map[32];

	if (unshare(CLONE_NEWUSER | CLONE_NEWNS))
		return -1;
	if (write_file("/proc/self/setgroups", "deny") && errno != ENOENT)
		return -1;
	snprintf(map, sizeof(map), "0 %d 1", uid);
	if (write_file("/proc/self/uid_map", map))
		return -1;
	snprintf(map, sizeof(map), "0 %d 1", gid);
	if (write_file("/proc/self/gid_map", map))
		return -1;
	if (setgid(0) || setuid(0))
		return -1;
	return mount("", "/", NULL, MS_REC | MS_PRIVATE, NULL);
}

FIXTURE(unmounted_tree) {
	char dir[PATH_LEN];
};

FIXTURE_SETUP(unmounted_tree)
{
	snprintf(self->dir, sizeof(self->dir), "/tmp/unmounted_tree.XXXXXX");
	ASSERT_NE(mkdtemp(self->dir), NULL);
	if (enter_userns()) {
		rmdir(self->dir);
		SKIP(return, "test requires user namespaces");
	}
	ASSERT_EQ(mount("tmpfs", self->dir, "tmpfs", 0, NULL), 0);
}

FIXTURE_TEARDOWN(unmounted_tree)
{
	umount2(self->dir, MNT_DETACH);
	rmdir(self->dir);
}

/* Every way to copy the mount @fd refers to must fail with EINVAL. */
static void assert_not_copyable(struct __test_metadata *_metadata, int fd,
				const char *target)
{
	char link[PATH_LEN];
	int tfd;

	snprintf(link, sizeof(link), "/proc/self/fd/%d", fd);
	EXPECT_EQ(mount(link, target, NULL, MS_BIND, NULL), -1);
	EXPECT_EQ(errno, EINVAL);
	EXPECT_EQ(mount(link, target, NULL, MS_BIND | MS_REC, NULL), -1);
	EXPECT_EQ(errno, EINVAL);

	tfd = sys_open_tree(fd, "", AT_EMPTY_PATH | OPEN_TREE_CLONE | OPEN_TREE_CLOEXEC);
	EXPECT_LT(tfd, 0);
	EXPECT_EQ(errno, EINVAL);
	if (tfd >= 0)
		close(tfd);

	tfd = sys_open_tree(fd, "", AT_EMPTY_PATH | AT_RECURSIVE | OPEN_TREE_CLONE |
			    OPEN_TREE_CLOEXEC);
	EXPECT_LT(tfd, 0);
	EXPECT_EQ(errno, EINVAL);
	if (tfd >= 0)
		close(tfd);
}

/*
 * A lazily unmounted bind mount of an nsfs file, kept alive by an fd, is no
 * longer accepted as the source of a bind mount or an open_tree() clone.
 * The internal nsfs mount and a mounted bind mount of it still are.
 */
TEST_F(unmounted_tree, detached_nsfs_bind_refused)
{
	char x[PATH_LEN], y[PATH_LEN], z[PATH_LEN];
	int fd, tfd;

	snprintf(x, sizeof(x), "%s/x", self->dir);
	snprintf(y, sizeof(y), "%s/y", self->dir);
	snprintf(z, sizeof(z), "%s/z", self->dir);
	ASSERT_EQ(touch(x), 0);
	ASSERT_EQ(touch(y), 0);
	ASSERT_EQ(touch(z), 0);

	ASSERT_EQ(mount("/proc/self/ns/net", x, NULL, MS_BIND, NULL), 0);
	fd = open(x, O_PATH | O_CLOEXEC);
	ASSERT_GE(fd, 0);
	ASSERT_EQ(umount2(x, MNT_DETACH), 0);

	assert_not_copyable(_metadata, fd, y);
	/* opening it is still fine */
	tfd = sys_open_tree(fd, "", AT_EMPTY_PATH | OPEN_TREE_CLOEXEC);
	ASSERT_GE(tfd, 0);
	close(tfd);
	close(fd);

	ASSERT_EQ(mount("/proc/self/ns/net", y, NULL, MS_BIND, NULL), 0);
	ASSERT_EQ(mount(y, z, NULL, MS_BIND, NULL), 0);
	tfd = sys_open_tree(AT_FDCWD, y, OPEN_TREE_CLONE | OPEN_TREE_CLOEXEC);
	ASSERT_GE(tfd, 0);
	close(tfd);
}

/* Bind-mount the pidfd @pidfd on @target the way pidfd_bind_mount does. */
static int bind_pidfd(int pidfd, const char *target)
{
	int tfd, ret;

	tfd = sys_open_tree(pidfd, "", AT_EMPTY_PATH | OPEN_TREE_CLONE | OPEN_TREE_CLOEXEC);
	if (tfd < 0)
		return -1;
	ret = sys_move_mount(tfd, "", AT_FDCWD, target, MOVE_MOUNT_F_EMPTY_PATH);
	close(tfd);
	return ret;
}

/* The same for a bind mount of a pidfd. */
TEST_F(unmounted_tree, detached_pidfs_bind_refused)
{
	char x[PATH_LEN], y[PATH_LEN];
	int pidfd, fd, tfd;

	snprintf(x, sizeof(x), "%s/x", self->dir);
	snprintf(y, sizeof(y), "%s/y", self->dir);
	ASSERT_EQ(touch(x), 0);
	ASSERT_EQ(touch(y), 0);

	pidfd = sys_pidfd_open(getpid(), 0);
	ASSERT_GE(pidfd, 0);
	ASSERT_EQ(bind_pidfd(pidfd, x), 0);
	fd = open(x, O_PATH | O_CLOEXEC);
	ASSERT_GE(fd, 0);
	ASSERT_EQ(umount2(x, MNT_DETACH), 0);

	assert_not_copyable(_metadata, fd, y);
	close(fd);

	ASSERT_EQ(bind_pidfd(pidfd, y), 0);
	tfd = sys_open_tree(AT_FDCWD, y, OPEN_TREE_CLONE | OPEN_TREE_CLOEXEC);
	ASSERT_GE(tfd, 0);
	close(tfd);
	close(pidfd);
}

/* Child exit codes. */
enum {
	CHILD_OK,
	CHILD_NS,		/* could not set up the mount namespace */
	CHILD_MOUNT,		/* could not set up the mounts */
	CHILD_PIPE,		/* the parent went away */
	CHILD_COPIED,		/* the detached tree was copied */
	CHILD_ERRNO,		/* refused, but not with EINVAL */
};

/*
 * In a mount namespace of its own: an nsfs bind mount on @x, an fd on it
 * and a bind mount of @s on top. Once the parent has unlinked @x
 * underneath, the first mount is detached and the second one, which
 * stayed attached to it, has been vacated. Neither may be copied.
 */
static int vacant_child(const char *x, const char *s, const char *y,
			int to_parent, int from_parent)
{
	char link[PATH_LEN];
	int fd, tfd;
	char c;

	if (unshare(CLONE_NEWNS) || mount("", "/", NULL, MS_REC | MS_PRIVATE, NULL))
		return CHILD_NS;
	if (mount("/proc/self/ns/net", x, NULL, MS_BIND, NULL))
		return CHILD_MOUNT;
	fd = open(x, O_PATH | O_CLOEXEC);
	if (fd < 0 || mount(s, x, NULL, MS_BIND, NULL))
		return CHILD_MOUNT;

	if (write(to_parent, "", 1) != 1 || read(from_parent, &c, 1) != 1)
		return CHILD_PIPE;

	tfd = sys_open_tree(fd, "", AT_EMPTY_PATH | AT_RECURSIVE | OPEN_TREE_CLONE |
			    OPEN_TREE_CLOEXEC);
	if (tfd >= 0) {
		close(tfd);
		return CHILD_COPIED;
	}
	if (errno != EINVAL)
		return CHILD_ERRNO;
	snprintf(link, sizeof(link), "/proc/self/fd/%d", fd);
	if (!mount(link, y, NULL, MS_BIND | MS_REC, NULL))
		return CHILD_COPIED;
	if (errno != EINVAL)
		return CHILD_ERRNO;
	/* the last reference on the detached mount collects the vacant one */
	close(fd);
	return CHILD_OK;
}

/*
 * unlink() of the child's mountpoint from here, where it is a plain file,
 * detaches the child's nsfs bind mount with the mount on top left attached
 * to it. The mount on top loses its last reference right there and is
 * vacated. The child must not be able to copy that tree.
 */
TEST_F(unmounted_tree, vacant_child_not_copied)
{
	char x[PATH_LEN], s[PATH_LEN], y[PATH_LEN];
	int to_parent[2], to_child[2];
	int status;
	pid_t pid;
	char c;

	snprintf(x, sizeof(x), "%s/x", self->dir);
	snprintf(s, sizeof(s), "%s/s", self->dir);
	snprintf(y, sizeof(y), "%s/y", self->dir);
	ASSERT_EQ(touch(x), 0);
	ASSERT_EQ(touch(s), 0);
	ASSERT_EQ(touch(y), 0);

	ASSERT_EQ(pipe(to_parent), 0);
	ASSERT_EQ(pipe(to_child), 0);

	pid = fork();
	ASSERT_GE(pid, 0);
	if (pid == 0) {
		close(to_parent[0]);
		close(to_child[1]);
		_exit(vacant_child(x, s, y, to_parent[1], to_child[0]));
	}
	close(to_parent[1]);
	close(to_child[0]);

	if (read(to_parent[0], &c, 1) != 1) {
		waitpid(pid, &status, 0);
		ASSERT_TRUE(false)
			TH_LOG("child exited with %d before the mounts were set up",
			       WEXITSTATUS(status));
	}

	/* not a mountpoint in this namespace, so the file can go */
	ASSERT_EQ(unlink(x), 0);

	ASSERT_EQ(write(to_child[1], "", 1), 1);
	ASSERT_EQ(waitpid(pid, &status, 0), pid);
	ASSERT_TRUE(WIFEXITED(status));
	ASSERT_EQ(WEXITSTATUS(status), CHILD_OK)
		TH_LOG("child exited with %d: %s", WEXITSTATUS(status),
		       WEXITSTATUS(status) == CHILD_COPIED ?
		       "the detached tree was copied" :
		       "the copy was refused with something other than EINVAL");
	close(to_parent[0]);
	close(to_child[1]);
}

/*
 * mount_setattr() may change the propagation of a detached tree while that
 * tree is still the root of an anonymous mount namespace, but not once the
 * tree has been dissolved and only a second fd keeps its root alive.
 */
TEST_F(unmounted_tree, detached_tree_setattr_refused)
{
	struct mount_attr attr = {
		.propagation = MS_SHARED,
	};
	char a[PATH_LEN], b[PATH_LEN];
	int tfd, fd;

	snprintf(a, sizeof(a), "%s/a", self->dir);
	snprintf(b, sizeof(b), "%s/a/b", self->dir);
	ASSERT_EQ(mkdir(a, 0755), 0);
	ASSERT_EQ(mount("tmpfs", a, "tmpfs", 0, NULL), 0);
	ASSERT_EQ(mkdir(b, 0755), 0);
	ASSERT_EQ(mount("tmpfs", b, "tmpfs", 0, NULL), 0);

	tfd = sys_open_tree(AT_FDCWD, self->dir, AT_RECURSIVE | OPEN_TREE_CLONE |
			    OPEN_TREE_CLOEXEC);
	ASSERT_GE(tfd, 0);
	ASSERT_EQ(sys_mount_setattr(tfd, "", AT_EMPTY_PATH | AT_RECURSIVE, &attr, sizeof(attr)), 0);
	attr.propagation = MS_PRIVATE;
	ASSERT_EQ(sys_mount_setattr(tfd, "", AT_EMPTY_PATH | AT_RECURSIVE, &attr, sizeof(attr)), 0);

	/* a second reference on the root, then dissolve the tree */
	fd = sys_open_tree(tfd, "", AT_EMPTY_PATH | OPEN_TREE_CLOEXEC);
	ASSERT_GE(fd, 0);
	close(tfd);

	attr.propagation = MS_SHARED;
	ASSERT_EQ(sys_mount_setattr(fd, "", AT_EMPTY_PATH | AT_RECURSIVE, &attr, sizeof(attr)), -1);
	ASSERT_EQ(errno, EINVAL);
	attr.propagation = MS_PRIVATE;
	ASSERT_EQ(sys_mount_setattr(fd, "", AT_EMPTY_PATH, &attr, sizeof(attr)), -1);
	ASSERT_EQ(errno, EINVAL);
	close(fd);
}

TEST_HARNESS_MAIN
