// SPDX-License-Identifier: GPL-2.0
/*
 * An unmounted mount that would have stayed attached to its unmounted parent
 * leaves a slot behind instead. A lookup on the parent at the mountpoint
 * finds knullfs: an empty read-only directory that is shared by every slot
 * and every kernel thread, so it can't be watched or locked and nothing can
 * be mounted on it. The mount itself is a root from then on. Where a file
 * was mounted, the stand-in is an empty regular file of the same instance.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <sched.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/fanotify.h>
#include <sys/file.h>
#include <sys/inotify.h>
#include <sys/mount.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <sys/syscall.h>
#include <sys/vfs.h>
#include <sys/wait.h>

#include "../../kselftest_harness.h"

#ifndef NULL_FS_MAGIC
#define NULL_FS_MAGIC 0x4E554C4C
#endif

#ifndef TMPFS_MAGIC
#define TMPFS_MAGIC 0x01021994
#endif

#ifndef F_SETDELEG
#define F_SETDELEG	(F_SETLEASE + 16)
#endif

/* struct delegation of <linux/fcntl.h>, which doesn't mix with <fcntl.h> */
struct delegation_req {
	uint32_t d_flags;
	uint16_t d_type;
	uint16_t __pad;
};

#define DIR_LEN 64
#define PATH_LEN 128

/* what the parent asks the child to do */
#define CMD_RMDIR	'r'
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
 * out descriptors on P and on C. rmdir() of @base/p from here unmounts P
 * together with C and the file bind. P and C are held by the descriptors and
 * the unmounted children leave their slots behind. On request the child
 * removes C's mountpoint through the bind.
 */
static int slot_child(const char *base, int to_parent, int from_parent)
{
	char p[PATH_LEN], c[PATH_LEN], q[PATH_LEN], qc[PATH_LEN];
	char f[PATH_LEN], src[PATH_LEN];
	int fds[2], ret;
	char cmd;

	if (unshare(CLONE_NEWNS) || mount("", "/", NULL, MS_REC | MS_PRIVATE, NULL))
		return 1;
	snprintf(p, sizeof(p), "%s/p", base);
	if (mkdir(p, 0755) || mount("tmpfs", p, "tmpfs", 0, NULL))
		return 2;
	snprintf(c, sizeof(c), "%s/p/covered", base);
	if (mkdir(c, 0755) || mount("tmpfs", c, "tmpfs", 0, NULL))
		return 3;
	snprintf(f, sizeof(f), "%s/p/file", base);
	snprintf(src, sizeof(src), "%s/p/src", base);
	if (touch(src) || touch(f) || mount(src, f, NULL, MS_BIND, NULL))
		return 4;
	snprintf(q, sizeof(q), "%s/q", base);
	if (mkdir(q, 0755) || mount(p, q, NULL, MS_BIND, NULL))
		return 5;
	fds[0] = open(p, O_PATH | O_DIRECTORY | O_CLOEXEC);
	fds[1] = open(c, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
	if (fds[0] < 0 || fds[1] < 0)
		return 6;
	if (write(to_parent, fds, sizeof(fds)) != sizeof(fds))
		return 7;

	snprintf(qc, sizeof(qc), "%s/q/covered", base);
	for (;;) {
		if (read(from_parent, &cmd, 1) != 1)
			return 8;
		switch (cmd) {
		case CMD_RMDIR:
			ret = rmdir(qc) ? errno : 0;
			if (write(to_parent, &ret, sizeof(ret)) != sizeof(ret))
				return 9;
			break;
		case CMD_QUIT:
			return 0;
		default:
			return 10;
		}
	}
}

FIXTURE(mount_slot) {
	char base[DIR_LEN];
	pid_t child;
	int to_child;
	int from_child;
	int dfd;	/* P, unmounted, held */
	int cfd;	/* C, unmounted, held */
	int fd;		/* what a lookup on P finds at C's mountpoint */
};

static int same_file(int fd1, int fd2)
{
	struct stat st1, st2;

	if (fstat(fd1, &st1) || fstat(fd2, &st2))
		return 0;
	return st1.st_dev == st2.st_dev && st1.st_ino == st2.st_ino;
}

FIXTURE_SETUP(mount_slot)
{
	int to_parent[2], to_child[2], fds[2], pidfd;
	char dir[PATH_LEN];
	struct statfs sf;

	self->child = 0;
	self->to_child = self->from_child = -1;
	self->dfd = self->cfd = self->fd = -1;

	snprintf(self->base, sizeof(self->base), "/tmp/mount_slot.XXXXXX");
	ASSERT_NE(mkdtemp(self->base), NULL);
	if (enter_userns()) {
		rmdir(self->base);
		SKIP(return, "test requires user namespaces");
	}
	ASSERT_EQ(mount("tmpfs", self->base, "tmpfs", 0, NULL), 0);

	snprintf(dir, sizeof(dir), "%s/p", self->base);
	ASSERT_EQ(pipe(to_parent), 0);
	ASSERT_EQ(pipe(to_child), 0);
	self->child = fork();
	ASSERT_GE(self->child, 0);
	if (self->child == 0) {
		close(to_parent[0]);
		close(to_child[1]);
		_exit(slot_child(self->base, to_parent[1], to_child[0]));
	}
	close(to_parent[1]);
	close(to_child[0]);
	self->to_child = to_child[1];
	self->from_child = to_parent[0];
	ASSERT_EQ(read(self->from_child, fds, sizeof(fds)), sizeof(fds));

	pidfd = syscall(__NR_pidfd_open, self->child, 0);
	ASSERT_GE(pidfd, 0);
	self->dfd = syscall(__NR_pidfd_getfd, pidfd, fds[0], 0);
	self->cfd = syscall(__NR_pidfd_getfd, pidfd, fds[1], 0);
	close(pidfd);
	ASSERT_GE(self->dfd, 0);
	ASSERT_GE(self->cfd, 0);

	/* unmounts P and C, C leaves its slot behind */
	ASSERT_EQ(rmdir(dir), 0);

	self->fd = openat(self->dfd, "covered", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
	ASSERT_GE(self->fd, 0);
	ASSERT_EQ(fstatfs(self->fd, &sf), 0);
	ASSERT_EQ(sf.f_type, NULL_FS_MAGIC);
}

FIXTURE_TEARDOWN(mount_slot)
{
	char cmd = CMD_QUIT;
	int status;

	if (self->fd >= 0)
		close(self->fd);
	if (self->cfd >= 0)
		close(self->cfd);
	if (self->dfd >= 0)
		close(self->dfd);
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

TEST_F(mount_slot, not_watchable)
{
	char p[PATH_LEN];
	int ifd, fan;

	snprintf(p, sizeof(p), "/proc/self/fd/%d", self->fd);

	ifd = inotify_init1(IN_CLOEXEC);
	ASSERT_GE(ifd, 0);
	EXPECT_EQ(inotify_add_watch(ifd, p, IN_OPEN), -1);
	EXPECT_EQ(errno, EINVAL);
	close(ifd);

	fan = fanotify_init(FAN_CLASS_NOTIF | FAN_CLOEXEC, O_RDONLY);
	if (fan < 0) {
		TH_LOG("fanotify_init(): %s, skipping the fanotify part", strerror(errno));
		return;
	}
	EXPECT_EQ(fanotify_mark(fan, FAN_MARK_ADD, FAN_OPEN, self->fd, NULL), -1);
	EXPECT_EQ(errno, EINVAL);
	close(fan);
}

TEST_F(mount_slot, not_lockable)
{
	struct flock fl = {
		.l_type = F_RDLCK,
		.l_whence = SEEK_SET,
	};

	EXPECT_EQ(flock(self->fd, LOCK_EX | LOCK_NB), -1);
	EXPECT_EQ(errno, ENOLCK);
	EXPECT_EQ(fcntl(self->fd, F_SETLK, &fl), -1);
	EXPECT_EQ(errno, ENOLCK);
	EXPECT_EQ(fcntl(self->fd, F_GETLK, &fl), -1);
	EXPECT_EQ(errno, ENOLCK);
}

/* a lease is refused for the owner and for everybody else alike */
TEST_F(mount_slot, not_leasable)
{
	struct delegation_req deleg = {
		.d_type = F_RDLCK,
	};

	EXPECT_EQ(fcntl(self->fd, F_SETLEASE, F_RDLCK), -1);
	EXPECT_TRUE(errno == EINVAL || errno == EACCES);
	EXPECT_EQ(fcntl(self->fd, F_SETDELEG, &deleg), -1);
	EXPECT_TRUE(errno == EINVAL || errno == EACCES);
}

TEST_F(mount_slot, not_mountable)
{
	char p[PATH_LEN];

	snprintf(p, sizeof(p), "/proc/self/fd/%d", self->fd);
	EXPECT_EQ(mount("tmpfs", p, "tmpfs", 0, NULL), -1);
	EXPECT_EQ(errno, ENOENT);
}

TEST_F(mount_slot, read_only)
{
	struct statvfs sv;

	EXPECT_EQ(mkdirat(self->fd, "x", 0755), -1);
	EXPECT_EQ(errno, ENOENT);
	EXPECT_EQ(fchmod(self->fd, 0777), -1);
	EXPECT_EQ(errno, EROFS);
	/* the immutable inode is checked before the read-only mount */
	EXPECT_EQ(faccessat(self->fd, ".", W_OK, 0), -1);
	EXPECT_EQ(errno, EPERM);
	ASSERT_EQ(fstatvfs(self->fd, &sv), 0);
	EXPECT_TRUE(sv.f_flag & ST_RDONLY);
}

/* the stand-in is a root of its own, ".." stays put */
TEST_F(mount_slot, island)
{
	int fd;

	fd = openat(self->fd, "..", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
	ASSERT_GE(fd, 0);
	EXPECT_TRUE(same_file(fd, self->fd));
	close(fd);
}

/*
 * C is alive for as long as the child holds it, but it can't be reached
 * through P anymore and it's a root of its own as well.
 */
TEST_F(mount_slot, held_child_detached)
{
	struct statfs sf;
	int fd;

	ASSERT_EQ(fstatfs(self->cfd, &sf), 0);
	EXPECT_EQ(sf.f_type, TMPFS_MAGIC);

	fd = openat(self->cfd, "..", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
	ASSERT_GE(fd, 0);
	EXPECT_TRUE(same_file(fd, self->cfd));
	close(fd);

	fd = openat(self->dfd, "covered", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
	ASSERT_GE(fd, 0);
	ASSERT_EQ(fstatfs(fd, &sf), 0);
	EXPECT_EQ(sf.f_type, NULL_FS_MAGIC);
	close(fd);
}

/*
 * The slot goes with its mountpoint: once the child has removed C's
 * mountpoint through the bind of P, the name is gone from P as well.
 * What was opened through the slot before stays open.
 */
TEST_F(mount_slot, slot_goes_with_mountpoint)
{
	char cmd = CMD_RMDIR;
	struct statfs sf;
	int ret;

	ASSERT_EQ(write(self->to_child, &cmd, 1), 1);
	ASSERT_EQ(read(self->from_child, &ret, sizeof(ret)), sizeof(ret));
	ASSERT_EQ(ret, 0);

	EXPECT_EQ(openat(self->dfd, "covered", O_RDONLY | O_DIRECTORY | O_CLOEXEC), -1);
	EXPECT_EQ(errno, ENOENT);
	ASSERT_EQ(fstatfs(self->fd, &sf), 0);
	EXPECT_EQ(sf.f_type, NULL_FS_MAGIC);
}

/* where a file was mounted, the stand-in is an empty regular file */
TEST_F(mount_slot, file_stand_in)
{
	char src[PATH_LEN], p[PATH_LEN];
	struct statfs sf;
	struct stat st;
	char c;
	int fd;

	fd = openat(self->dfd, "file", O_RDONLY | O_CLOEXEC);
	ASSERT_GE(fd, 0);
	ASSERT_EQ(fstat(fd, &st), 0);
	EXPECT_TRUE(S_ISREG(st.st_mode));
	ASSERT_EQ(fstatfs(fd, &sf), 0);
	EXPECT_EQ(sf.f_type, NULL_FS_MAGIC);
	EXPECT_EQ(read(fd, &c, 1), 0);
	EXPECT_EQ(flock(fd, LOCK_EX | LOCK_NB), -1);
	EXPECT_EQ(errno, ENOLCK);

	snprintf(src, sizeof(src), "%s/src", self->base);
	ASSERT_EQ(touch(src), 0);
	snprintf(p, sizeof(p), "/proc/self/fd/%d", fd);
	EXPECT_EQ(mount(src, p, NULL, MS_BIND, NULL), -1);
	EXPECT_EQ(errno, ENOENT);
	close(fd);

	EXPECT_EQ(openat(self->dfd, "file", O_WRONLY | O_CLOEXEC), -1);
	EXPECT_EQ(errno, EPERM);
	EXPECT_EQ(openat(self->dfd, "file", O_RDONLY | O_DIRECTORY | O_CLOEXEC), -1);
	EXPECT_EQ(errno, ENOTDIR);
}

TEST_HARNESS_MAIN
