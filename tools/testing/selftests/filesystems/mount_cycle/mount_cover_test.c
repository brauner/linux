// SPDX-License-Identifier: GPL-2.0
/*
 * An unmounted mount that would have stayed attached to its unmounted parent
 * leaves a cover behind instead. A walk on the parent that gets to the
 * mountpoint fails there with ENOENT: the mount it would have crossed onto is
 * gone. Nothing can be opened, pinned or mounted there, where a directory was
 * mounted and where a file was. The mount itself is a root from then on.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/mount.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/vfs.h>
#include <sys/wait.h>

#include "../../kselftest_harness.h"

#ifndef TMPFS_MAGIC
#define TMPFS_MAGIC 0x01021994
#endif

#define DIR_LEN 64
#define PATH_LEN 128

/* what the parent asks the child to do */
#define CMD_RMDIR	'r'
#define CMD_CLOSE_T	't'
#define CMD_QUIT	'q'

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

	prctl(PR_SET_DUMPABLE, 1);
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

/*
 * The child mounts P on @base/p, C on P/covered and the file P/src on P/file
 * in a mount namespace of its own, binds P a second time at @base/q and hands
 * out descriptors on P, on C and on C's mountpoint from before C was
 * mounted. rmdir() of @base/p from here unmounts P
 * together with C and the file bind. P and C are held by the descriptors and
 * the unmounted children leave their covers behind. On request the child
 * removes C's mountpoint through the bind.
 *
 * It also mounts T on @base/t with a child on T/covered, binds T at @base/u
 * with a second child on the same dentry and hands out descriptors on T and
 * U. rmdir() of both from here leaves two covers on one mountpoint. On request
 * the child lets go of T.
 */
static int cover_child(const char *base, int to_parent, int from_parent)
{
	char p[PATH_LEN], c[PATH_LEN], q[PATH_LEN], qc[PATH_LEN];
	char f[PATH_LEN], src[PATH_LEN], t[PATH_LEN], u[PATH_LEN], tc[PATH_LEN];
	int fds[5], ret;
	char cmd;

	if (unshare(CLONE_NEWNS) || mount("", "/", NULL, MS_REC | MS_PRIVATE, NULL))
		return 1;
	snprintf(p, sizeof(p), "%s/p", base);
	if (mkdir(p, 0755) || mount("tmpfs", p, "tmpfs", 0, NULL))
		return 2;
	snprintf(c, sizeof(c), "%s/p/covered", base);
	if (mkdir(c, 0755))
		return 3;
	/* the mountpoint itself, from before anything was mounted on it */
	fds[4] = open(c, O_PATH | O_DIRECTORY | O_CLOEXEC);
	if (fds[4] < 0 || mount("tmpfs", c, "tmpfs", 0, NULL))
		return 3;
	snprintf(f, sizeof(f), "%s/p/file", base);
	snprintf(src, sizeof(src), "%s/p/src", base);
	if (touch(src) || touch(f) || mount(src, f, NULL, MS_BIND, NULL))
		return 4;
	snprintf(q, sizeof(q), "%s/q", base);
	if (mkdir(q, 0755) || mount(p, q, NULL, MS_BIND, NULL))
		return 5;
	snprintf(t, sizeof(t), "%s/t", base);
	if (mkdir(t, 0755) || mount("tmpfs", t, "tmpfs", 0, NULL))
		return 6;
	snprintf(tc, sizeof(tc), "%s/t/covered", base);
	if (mkdir(tc, 0755) || mount("tmpfs", tc, "tmpfs", 0, NULL))
		return 7;
	snprintf(u, sizeof(u), "%s/u", base);
	if (mkdir(u, 0755) || mount(t, u, NULL, MS_BIND, NULL))
		return 8;
	snprintf(tc, sizeof(tc), "%s/u/covered", base);
	if (mount("tmpfs", tc, "tmpfs", 0, NULL))
		return 9;
	fds[0] = open(p, O_PATH | O_DIRECTORY | O_CLOEXEC);
	fds[1] = open(c, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
	fds[2] = open(t, O_PATH | O_DIRECTORY | O_CLOEXEC);
	fds[3] = open(u, O_PATH | O_DIRECTORY | O_CLOEXEC);
	if (fds[0] < 0 || fds[1] < 0 || fds[2] < 0 || fds[3] < 0)
		return 10;
	if (write(to_parent, fds, sizeof(fds)) != sizeof(fds))
		return 11;

	snprintf(qc, sizeof(qc), "%s/q/covered", base);
	for (;;) {
		if (read(from_parent, &cmd, 1) != 1)
			return 12;
		switch (cmd) {
		case CMD_RMDIR:
			ret = rmdir(qc) ? errno : 0;
			if (write(to_parent, &ret, sizeof(ret)) != sizeof(ret))
				return 13;
			break;
		case CMD_CLOSE_T:
			ret = close(fds[2]) ? errno : 0;
			if (write(to_parent, &ret, sizeof(ret)) != sizeof(ret))
				return 13;
			break;
		case CMD_QUIT:
			return 0;
		default:
			return 14;
		}
	}
}

FIXTURE(mount_cover) {
	char base[DIR_LEN];
	pid_t child;
	int to_child;
	int from_child;
	int dfd;	/* P, unmounted, held */
	int cfd;	/* C, unmounted, held */
	int mfd;	/* C's mountpoint in P, opened before C was mounted */
	int tfd;	/* T, unmounted, held */
	int ufd;	/* U, a bind of T, unmounted, held */
};

/*
 * Everything the setup has made. The harness does not run the teardown
 * when an assertion of the setup fails, so the setup calls this itself.
 */
static void cover_cleanup(FIXTURE_DATA(mount_cover) *self)
{
	char cmd = CMD_QUIT;
	int status;

	if (self->cfd >= 0)
		close(self->cfd);
	if (self->dfd >= 0)
		close(self->dfd);
	if (self->mfd >= 0)
		close(self->mfd);
	if (self->tfd >= 0)
		close(self->tfd);
	if (self->ufd >= 0)
		close(self->ufd);
	if (self->child > 0) {
		if (write(self->to_child, &cmd, 1) != 1)
			kill(self->child, SIGKILL);
		waitpid(self->child, &status, 0);
	}
	if (self->to_child >= 0)
		close(self->to_child);
	if (self->from_child >= 0)
		close(self->from_child);
	umount2(self->base, MNT_DETACH);
	rmdir(self->base);
}

static int same_file(int fd1, int fd2)
{
	struct stat st1, st2;

	if (fstat(fd1, &st1) || fstat(fd2, &st2))
		return 0;
	return st1.st_dev == st2.st_dev && st1.st_ino == st2.st_ino;
}

FIXTURE_SETUP(mount_cover)
{
	int to_parent[2], to_child[2], fds[5], pidfd, status;
	char dir[PATH_LEN];

	self->child = 0;
	self->to_child = self->from_child = -1;
	self->dfd = self->cfd = self->mfd = self->tfd = self->ufd = -1;

	snprintf(self->base, sizeof(self->base), "/tmp/mount_cover.XXXXXX");
	ASSERT_NE(mkdtemp(self->base), NULL);
	if (enter_userns()) {
		cover_cleanup(self);
		SKIP(return, "test requires user namespaces");
	}
	ASSERT_EQ(mount("tmpfs", self->base, "tmpfs", 0, NULL), 0)
		cover_cleanup(self);

	snprintf(dir, sizeof(dir), "%s/p", self->base);
	ASSERT_EQ(pipe(to_parent), 0)
		cover_cleanup(self);
	ASSERT_EQ(pipe(to_child), 0)
		cover_cleanup(self);
	self->child = fork();
	ASSERT_GE(self->child, 0)
		cover_cleanup(self);
	if (self->child == 0) {
		close(to_parent[0]);
		close(to_child[1]);
		_exit(cover_child(self->base, to_parent[1], to_child[0]));
	}
	close(to_parent[1]);
	close(to_child[0]);
	self->to_child = to_child[1];
	self->from_child = to_parent[0];
	if (read(self->from_child, fds, sizeof(fds)) != sizeof(fds)) {
		pid_t pid = self->child;

		waitpid(pid, &status, 0);
		self->child = 0;
		cover_cleanup(self);
		ASSERT_TRUE(false)
			TH_LOG("child failed to set up: %s %d",
			       WIFEXITED(status) ? "step" : "signal",
			       WIFEXITED(status) ? WEXITSTATUS(status) : WTERMSIG(status));
	}

	pidfd = syscall(__NR_pidfd_open, self->child, 0);
	ASSERT_GE(pidfd, 0)
		cover_cleanup(self);
	self->dfd = syscall(__NR_pidfd_getfd, pidfd, fds[0], 0);
	self->cfd = syscall(__NR_pidfd_getfd, pidfd, fds[1], 0);
	self->tfd = syscall(__NR_pidfd_getfd, pidfd, fds[2], 0);
	self->ufd = syscall(__NR_pidfd_getfd, pidfd, fds[3], 0);
	self->mfd = syscall(__NR_pidfd_getfd, pidfd, fds[4], 0);
	close(pidfd);
	ASSERT_GE(self->dfd, 0)
		cover_cleanup(self);
	ASSERT_GE(self->cfd, 0)
		cover_cleanup(self);
	ASSERT_GE(self->mfd, 0)
		cover_cleanup(self);
	ASSERT_GE(self->tfd, 0)
		cover_cleanup(self);
	ASSERT_GE(self->ufd, 0)
		cover_cleanup(self);

	/* unmounts P and C, C leaves its cover behind */
	ASSERT_EQ(rmdir(dir), 0)
		cover_cleanup(self);
	/* unmounts T and U with their children, two covers on one mountpoint */
	snprintf(dir, sizeof(dir), "%s/t", self->base);
	ASSERT_EQ(rmdir(dir), 0)
		cover_cleanup(self);
	snprintf(dir, sizeof(dir), "%s/u", self->base);
	ASSERT_EQ(rmdir(dir), 0)
		cover_cleanup(self);

	/* the cover fails the walk, there is nothing to hold */
	ASSERT_EQ(openat(self->dfd, "covered", O_PATH | O_CLOEXEC), -1)
		cover_cleanup(self);
	ASSERT_EQ(errno, ENOENT)
		cover_cleanup(self);
}

FIXTURE_TEARDOWN(mount_cover)
{
	cover_cleanup(self);
}

/* every walk that gets to the cover fails there, however it gets there */
TEST_F(mount_cover, not_reachable)
{
	struct stat st;
	int fd;

	EXPECT_EQ(openat(self->dfd, "covered", O_RDONLY | O_DIRECTORY | O_CLOEXEC), -1);
	EXPECT_EQ(errno, ENOENT);
	EXPECT_EQ(openat(self->dfd, "covered", O_PATH | O_CLOEXEC), -1);
	EXPECT_EQ(errno, ENOENT);
	EXPECT_EQ(fstatat(self->dfd, "covered", &st, 0), -1);
	EXPECT_EQ(errno, ENOENT);
	EXPECT_EQ(faccessat(self->dfd, "covered", F_OK, 0), -1);
	EXPECT_EQ(errno, ENOENT);
	/* nor below it */
	EXPECT_EQ(openat(self->dfd, "covered/x", O_RDONLY | O_CLOEXEC), -1);
	EXPECT_EQ(errno, ENOENT);
	/* where a file was mounted it is the same */
	EXPECT_EQ(openat(self->dfd, "file", O_RDONLY | O_CLOEXEC), -1);
	EXPECT_EQ(errno, ENOENT);
	EXPECT_EQ(fstatat(self->dfd, "file", &st, 0), -1);
	EXPECT_EQ(errno, ENOENT);
	/* the unmounted parent itself is fine */
	fd = openat(self->dfd, ".", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
	ASSERT_GE(fd, 0);
	close(fd);
}

/*
 * Nothing can be mounted on the cover. The walk to it fails, and a
 * descriptor on the mountpoint from before the mount gets the same
 * answer from the mount code itself.
 */
TEST_F(mount_cover, not_mountable)
{
	char p[PATH_LEN];

	snprintf(p, sizeof(p), "/proc/self/fd/%d/covered", self->dfd);
	EXPECT_EQ(mount("tmpfs", p, "tmpfs", 0, NULL), -1);
	EXPECT_EQ(errno, ENOENT);

	snprintf(p, sizeof(p), "/proc/self/fd/%d", self->mfd);
	EXPECT_EQ(mount("tmpfs", p, "tmpfs", 0, NULL), -1);
	EXPECT_EQ(errno, ENOENT);
}

/*
 * C is alive for as long as the child holds it, but it can't be reached
 * through P anymore and it's a root of its own as well.
 */
TEST_F(mount_cover, held_child_detached)
{
	struct statfs sf;
	int fd;

	ASSERT_EQ(fstatfs(self->cfd, &sf), 0);
	EXPECT_EQ(sf.f_type, TMPFS_MAGIC);

	fd = openat(self->cfd, "..", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
	ASSERT_GE(fd, 0);
	EXPECT_TRUE(same_file(fd, self->cfd));
	close(fd);

	EXPECT_EQ(openat(self->dfd, "covered", O_RDONLY | O_DIRECTORY | O_CLOEXEC), -1);
	EXPECT_EQ(errno, ENOENT);
}

/*
 * Once the child has removed C's mountpoint through the bind of P, the
 * name is gone from P and a lookup fails with ENOENT before it gets to
 * the cover.
 */
TEST_F(mount_cover, removed_mountpoint)
{
	char cmd = CMD_RMDIR;
	int ret;

	ASSERT_EQ(write(self->to_child, &cmd, 1), 1);
	ASSERT_EQ(read(self->from_child, &ret, sizeof(ret)), sizeof(ret));
	ASSERT_EQ(ret, 0);

	EXPECT_EQ(openat(self->dfd, "covered", O_RDONLY | O_DIRECTORY | O_CLOEXEC), -1);
	EXPECT_EQ(errno, ENOENT);
}

/*
 * Two unmounted parents left covers on the same dentry. A lookup on
 * either fails, and U's cover stays when T goes.
 */
TEST_F(mount_cover, shared_mountpoint)
{
	char cmd = CMD_CLOSE_T;
	int ret;

	EXPECT_EQ(openat(self->tfd, "covered", O_RDONLY | O_DIRECTORY | O_CLOEXEC), -1);
	EXPECT_EQ(errno, ENOENT);
	EXPECT_EQ(openat(self->ufd, "covered", O_RDONLY | O_DIRECTORY | O_CLOEXEC), -1);
	EXPECT_EQ(errno, ENOENT);

	/* the last references to T go, with T its cover */
	ASSERT_EQ(write(self->to_child, &cmd, 1), 1);
	ASSERT_EQ(read(self->from_child, &ret, sizeof(ret)), sizeof(ret));
	ASSERT_EQ(ret, 0);
	close(self->tfd);
	self->tfd = -1;

	EXPECT_EQ(openat(self->ufd, "covered", O_RDONLY | O_DIRECTORY | O_CLOEXEC), -1);
	EXPECT_EQ(errno, ENOENT);
}

TEST_HARNESS_MAIN
