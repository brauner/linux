// SPDX-License-Identifier: GPL-2.0
/*
 * A mount that loses its last reference while it is still attached to an
 * unmounted parent is vacated in place: a nullfs directory stands in for it
 * at the mountpoint and the parent owns it. The parent lets go of it when
 * the mountpoint is removed underneath it or when the parent itself dies.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <sched.h>
#include <stdio.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/vfs.h>
#include <sys/wait.h>
#include <unistd.h>
#include <linux/magic.h>
#include <linux/stat.h>

#include "../../kselftest_harness.h"

static int sys_pidfd_open(pid_t pid, unsigned int flags)
{
	return syscall(__NR_pidfd_open, pid, flags);
}

static int sys_pidfd_getfd(int pidfd, int fd, unsigned int flags)
{
	return syscall(__NR_pidfd_getfd, pidfd, fd, flags);
}

FIXTURE(vacant_mount) {
};

FIXTURE_SETUP(vacant_mount)
{
	if (geteuid() != 0)
		SKIP(return, "test requires CAP_SYS_ADMIN");

	ASSERT_EQ(unshare(CLONE_NEWNS), 0);
	ASSERT_EQ(mount("", "/", NULL, MS_REC | MS_PRIVATE, NULL), 0);

	rmdir("/mnt_dir");
	ASSERT_EQ(mkdir("/mnt_dir", 0755), 0);
	ASSERT_EQ(mount("tmpfs", "/mnt_dir", "tmpfs", 0, NULL), 0);
}

FIXTURE_TEARDOWN(vacant_mount)
{
	umount2("/mnt_dir", MNT_DETACH);
	rmdir("/mnt_dir");
}

/* A child's mount P on /mnt_dir/<name>, held here through a directory fd. */
struct pinned {
	pid_t pid;
	int dfd;
	int to_child;
};

/*
 * In its own mount namespace the child mounts a tmpfs P on /mnt_dir/@name
 * and a tmpfs C on P/covered with a file in it, and hands us a directory fd
 * on P. It stays alive until told to go, so that P is still mounted in its
 * namespace when we remove the directory below it.
 */
static void pinned_setup(struct __test_metadata *_metadata, const char *name,
			 struct pinned *p)
{
	int to_parent[2], to_child[2];
	int fd = -1, pidfd, status;
	char path[64];

	ASSERT_EQ(pipe(to_parent), 0);
	ASSERT_EQ(pipe(to_child), 0);

	p->pid = fork();
	ASSERT_GE(p->pid, 0);
	if (p->pid == 0) {
		char c;

		if (unshare(CLONE_NEWNS) ||
		    mount("", "/", NULL, MS_REC | MS_PRIVATE, NULL))
			_exit(1);
		snprintf(path, sizeof(path), "/mnt_dir/%s", name);
		if (mkdir(path, 0755) || mount("tmpfs", path, "tmpfs", 0, NULL))
			_exit(2);
		snprintf(path, sizeof(path), "/mnt_dir/%s/covered", name);
		if (mkdir(path, 0755) || mount("tmpfs", path, "tmpfs", 0, NULL))
			_exit(3);
		snprintf(path, sizeof(path), "/mnt_dir/%s/covered/file", name);
		fd = open(path, O_CREAT | O_WRONLY, 0644);
		if (fd < 0)
			_exit(4);
		close(fd);
		snprintf(path, sizeof(path), "/mnt_dir/%s", name);
		fd = open(path, O_PATH | O_DIRECTORY);
		if (fd < 0)
			_exit(5);
		if (write(to_parent[1], &fd, sizeof(fd)) != sizeof(fd))
			_exit(6);
		if (read(to_child[0], &c, 1) != 1)
			_exit(7);
		_exit(0);
	}

	if (read(to_parent[0], &fd, sizeof(fd)) != sizeof(fd)) {
		waitpid(p->pid, &status, 0);
		ASSERT_TRUE(false)
			TH_LOG("child failed to set up: exit status %d",
			       WIFEXITED(status) ? WEXITSTATUS(status) : -1);
	}
	pidfd = sys_pidfd_open(p->pid, 0);
	ASSERT_GE(pidfd, 0);
	p->dfd = sys_pidfd_getfd(pidfd, fd, 0);
	ASSERT_GE(p->dfd, 0);
	close(pidfd);
	close(to_parent[0]);
	close(to_parent[1]);
	close(to_child[0]);
	p->to_child = to_child[1];
}

/* The child goes, and with our fd closed nothing holds P anymore. */
static void pinned_release(struct __test_metadata *_metadata, struct pinned *p)
{
	int status;

	ASSERT_EQ(write(p->to_child, "", 1), 1);
	ASSERT_EQ(waitpid(p->pid, &status, 0), p->pid);
	ASSERT_EQ(status, 0);
	close(p->to_child);
	close(p->dfd);
}

/*
 * rmdir of P's mountpoint from here, where it is a plain directory, lazily
 * unmounts P with C still attached below it. Our fd holds P, nothing holds
 * C, so C is vacated in place by this task and the release of its tmpfs
 * runs from task work when rmdir() returns.
 */
static void vacate_covered(struct __test_metadata *_metadata, const char *name)
{
	char path[64];

	snprintf(path, sizeof(path), "/mnt_dir/%s", name);
	ASSERT_EQ(rmdir(path), 0);
}

/* The unique mount id of whatever is mounted on P/covered. */
static __u64 covered_mnt_id(struct __test_metadata *_metadata, int dfd)
{
	struct statx stx;

	ASSERT_EQ(statx(dfd, "covered", 0, STATX_MNT_ID_UNIQUE, &stx), 0);
	ASSERT_TRUE(stx.stx_mask & STATX_MNT_ID_UNIQUE);
	return stx.stx_mnt_id;
}

/* What is left at the mountpoint is a nullfs directory. */
static void assert_vacant(struct __test_metadata *_metadata, int dfd)
{
	struct statfs sf;
	int cfd;

	cfd = openat(dfd, "covered", O_RDONLY | O_DIRECTORY);
	ASSERT_GE(cfd, 0);
	ASSERT_EQ(fstatfs(cfd, &sf), 0);
	ASSERT_EQ(sf.f_type, NULL_FS_MAGIC);
	close(cfd);
}

/*
 * A vacant mount is a new mount at the old place and has a mount id of its
 * own. rmdir of its mountpoint through our fd on P detaches it from P, which
 * must let go of it and live on without it.
 */
TEST_F(vacant_mount, mountpoint_removed)
{
	__u64 before, after;
	struct pinned p;

	pinned_setup(_metadata, "pinned", &p);
	before = covered_mnt_id(_metadata, p.dfd);

	vacate_covered(_metadata, "pinned");
	assert_vacant(_metadata, p.dfd);
	after = covered_mnt_id(_metadata, p.dfd);
	EXPECT_NE(before, after);

	ASSERT_EQ(unlinkat(p.dfd, "covered", AT_REMOVEDIR), 0);
	EXPECT_EQ(faccessat(p.dfd, "covered", F_OK, 0), -1);
	EXPECT_EQ(errno, ENOENT);

	/* P is still there and still a tmpfs of its own. */
	EXPECT_EQ(faccessat(p.dfd, ".", F_OK, 0), 0);
	pinned_release(_metadata, &p);
}

/* The parent's death takes the vacant mount below it along. */
TEST_F(vacant_mount, goes_with_parent)
{
	struct pinned p;

	pinned_setup(_metadata, "pinned", &p);
	vacate_covered(_metadata, "pinned");
	assert_vacant(_metadata, p.dfd);
	pinned_release(_metadata, &p);
}

TEST_HARNESS_MAIN
