// SPDX-License-Identifier: GPL-2.0
/*
 * Removing the name of a dentry detaches the mounts on it in every mount
 * namespace. A mount on the root of its parent isn't reached by that name
 * but by crossing onto the parent, so it has to stay: M1 binds F/secret on
 * T/x and M2 covers T/x on top of M1. When F/secret goes away in a mount
 * namespace in which nothing is mounted on it, T/x still has to show M2.
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
#include <sys/wait.h>

#include "../../kselftest_harness.h"

#define DIR_LEN		64
#define PATH_LEN	128
#define SECRET		"secret"
#define MASK		"mask"
#define RACE_ROUNDS	300

/* exit codes of the children, each test says what they mean */
enum {
	CHILD_OK,
	CHILD_SETUP,
	CHILD_STEP1,
	CHILD_STEP2,
	CHILD_STEP3,
};

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

static int create_file(const char *path, const char *s)
{
	ssize_t n = -1;
	int fd;

	fd = open(path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0644);
	if (fd >= 0) {
		n = write(fd, s, strlen(s));
		close(fd);
	}
	return n == (ssize_t)strlen(s) ? 0 : -1;
}

/* Root in a new user namespace with a copy of the mount namespace. */
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
	return setgid(0) || setuid(0) ? -1 : 0;
}

static int wait_child(pid_t pid)
{
	int status;

	if (waitpid(pid, &status, 0) != pid || !WIFEXITED(status))
		return -1;
	return WEXITSTATUS(status);
}

static int wait_byte(int fd)
{
	char c;

	return read(fd, &c, 1) == 1 ? 0 : -1;
}

static int send_byte(int fd)
{
	return write(fd, "x", 1) == 1 ? 0 : -1;
}

/* What @path reads, "" if it can't be read. */
static int read_word(const char *path, char *buf, size_t len)
{
	ssize_t n = 0;
	int fd;

	fd = open(path, O_RDONLY | O_CLOEXEC);
	if (fd >= 0) {
		n = read(fd, buf, len - 1);
		close(fd);
	}
	buf[n > 0 ? n : 0] = 0;
	return fd < 0 ? -1 : 0;
}

FIXTURE(detach_mounts) {
	char base[DIR_LEN];
	int to_child[2];
	int from_child[2];
};

FIXTURE_SETUP(detach_mounts)
{
	char p[PATH_LEN];

	if (geteuid())
		SKIP(return, "test requires root");

	snprintf(self->base, sizeof(self->base), "/tmp/detach_mounts.XXXXXX");
	ASSERT_NE(mkdtemp(self->base), NULL);
	ASSERT_EQ(unshare(CLONE_NEWNS), 0);
	ASSERT_EQ(mount("", "/", NULL, MS_REC | MS_PRIVATE, NULL), 0);
	ASSERT_EQ(mount("tmpfs", self->base, "tmpfs", 0, "mode=0755"), 0);
	snprintf(p, sizeof(p), "%s/F", self->base);
	ASSERT_EQ(mkdir(p, 0755), 0);
	ASSERT_EQ(mount("tmpfs", p, "tmpfs", 0, "mode=0755"), 0);
	snprintf(p, sizeof(p), "%s/F/secret", self->base);
	ASSERT_EQ(create_file(p, SECRET), 0);
	snprintf(p, sizeof(p), "%s/F/mask", self->base);
	ASSERT_EQ(create_file(p, MASK), 0);
	snprintf(p, sizeof(p), "%s/F/other", self->base);
	ASSERT_EQ(create_file(p, "other"), 0);
	snprintf(p, sizeof(p), "%s/T", self->base);
	ASSERT_EQ(mkdir(p, 0755), 0);
	snprintf(p, sizeof(p), "%s/T/x", self->base);
	ASSERT_EQ(create_file(p, "x"), 0);
	ASSERT_EQ(pipe(self->to_child), 0);
	ASSERT_EQ(pipe(self->from_child), 0);
}

FIXTURE_TEARDOWN(detach_mounts)
{
	umount2(self->base, MNT_DETACH);
	rmdir(self->base);
}

/*
 * The child binds F/secret on T/x (M1) and F/mask on top of it (M2) in a
 * mount namespace of its own and locks both by entering a user namespace.
 * It reads T/x before and after the parent removed the name F/secret, and
 * MASK is the only thing it may read.
 */
static int stacked_child(const char *base, int to_parent, int from_parent)
{
	char secret[PATH_LEN], mask[PATH_LEN], x[PATH_LEN], buf[16];

	snprintf(secret, sizeof(secret), "%s/F/secret", base);
	snprintf(mask, sizeof(mask), "%s/F/mask", base);
	snprintf(x, sizeof(x), "%s/T/x", base);

	if (unshare(CLONE_NEWNS))
		return CHILD_SETUP;
	if (mount(secret, x, NULL, MS_BIND, NULL) ||
	    mount(mask, x, NULL, MS_BIND, NULL))
		return CHILD_SETUP;
	if (enter_userns())
		return CHILD_SETUP;
	if (read_word(x, buf, sizeof(buf)) || strcmp(buf, MASK))
		return CHILD_STEP1;
	/* the cover is locked */
	if (!umount2(x, MNT_DETACH) || errno != EINVAL)
		return CHILD_STEP2;
	if (send_byte(to_parent) || wait_byte(from_parent))
		return CHILD_SETUP;
	if (read_word(x, buf, sizeof(buf)) || strcmp(buf, MASK))
		return CHILD_STEP3;
	return CHILD_OK;
}

static int stacked(FIXTURE_DATA(detach_mounts) *self, bool by_rename)
{
	char p[PATH_LEN], q[PATH_LEN];
	pid_t pid;

	pid = fork();
	if (pid < 0)
		return -1;
	if (pid == 0)
		_exit(stacked_child(self->base, self->from_child[1],
				    self->to_child[0]));
	if (wait_byte(self->from_child[0]))
		return -1;
	/* nothing is mounted on F/secret here */
	snprintf(p, sizeof(p), "%s/F/secret", self->base);
	snprintf(q, sizeof(q), "%s/F/other", self->base);
	if (by_rename ? rename(q, p) : unlink(p))
		return -1;
	if (send_byte(self->to_child[1]))
		return -1;
	return wait_child(pid);
}

TEST_F(detach_mounts, overmount_stays_after_unlink)
{
	int ret = stacked(self, false);

	TH_LOG("child exit code %d", ret);
	EXPECT_EQ(ret, CHILD_OK);
}

TEST_F(detach_mounts, overmount_stays_after_rename)
{
	int ret = stacked(self, true);

	TH_LOG("child exit code %d", ret);
	EXPECT_EQ(ret, CHILD_OK);
}

/*
 * M1 binds F/secret on itself and M2 covers it. A walk that crossed onto
 * M1 before F/secret went away must not end on the file, whatever else
 * it finds there. The walk goes through a magic link so that the last
 * component is looked up in refwalk. Each round makes the mounts again
 * in a fresh copy of the mount namespace.
 */
static int selfbind_child(const char *base, int to_parent, int from_parent)
{
	char secret[PATH_LEN], mask[PATH_LEN], f[PATH_LEN], path[PATH_LEN];
	int hits = 0;

	snprintf(secret, sizeof(secret), "%s/F/secret", base);
	snprintf(mask, sizeof(mask), "%s/F/mask", base);
	snprintf(f, sizeof(f), "%s/F", base);

	for (int round = 0; round < RACE_ROUNDS; round++) {
		char buf[16];
		int dfd;

		if (wait_byte(from_parent))
			return CHILD_SETUP;
		if (unshare(CLONE_NEWNS))
			return CHILD_SETUP;
		if (mount(secret, secret, NULL, MS_BIND, NULL) ||
		    mount(mask, secret, NULL, MS_BIND, NULL))
			return CHILD_SETUP;
		/* on the copy of F that carries this round's mounts */
		dfd = open(f, O_PATH | O_DIRECTORY | O_CLOEXEC);
		if (dfd < 0)
			return CHILD_SETUP;
		snprintf(path, sizeof(path), "/proc/self/fd/%d/secret", dfd);
		if (send_byte(to_parent))
			return CHILD_SETUP;
		for (int i = 0; i < 20000; i++) {
			if (read_word(path, buf, sizeof(buf)))
				break;
			if (!strcmp(buf, SECRET)) {
				hits++;
				break;
			}
		}
		close(dfd);
		if (send_byte(to_parent))
			return CHILD_SETUP;
	}
	return hits ? CHILD_STEP1 : CHILD_OK;
}

TEST_F(detach_mounts, self_bind_race)
{
	char p[PATH_LEN];
	pid_t pid;
	int ret;

	pid = fork();
	ASSERT_GE(pid, 0);
	if (pid == 0)
		_exit(selfbind_child(self->base, self->from_child[1],
				     self->to_child[0]));
	snprintf(p, sizeof(p), "%s/F/secret", self->base);
	srand(getpid());
	for (int round = 0; round < RACE_ROUNDS; round++) {
		ASSERT_EQ(create_file(p, SECRET), 0);
		ASSERT_EQ(send_byte(self->to_child[1]), 0);
		ASSERT_EQ(wait_byte(self->from_child[0]), 0);
		usleep(rand() % 2000);
		ASSERT_EQ(unlink(p), 0);
		ASSERT_EQ(wait_byte(self->from_child[0]), 0);
	}
	ret = wait_child(pid);
	TH_LOG("child exit code %d", ret);
	EXPECT_EQ(ret, CHILD_OK);
}

TEST_HARNESS_MAIN
