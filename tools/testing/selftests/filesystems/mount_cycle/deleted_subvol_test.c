// SPDX-License-Identifier: GPL-2.0
/*
 * A btrfs subvolume can be deleted while a task has its cwd in it and
 * mounts sit on names below it, and btrfs keeps answering for those
 * names until the cleaner has dropped the tree. The mounts are detached
 * and their traps stay on the mount they hung from: a walk from that cwd
 * fails where a mount was instead of reading what it covered, and the
 * task doesn't get a copy of the mount without the traps either, its
 * unshare(CLONE_NEWNS) from inside the deleted subvolume is refused.
 *
 * Requires root, a loop device and mkfs.btrfs.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <linux/btrfs.h>
#include <linux/loop.h>

#include "../../kselftest_harness.h"

#define IMAGE_SIZE	(256 << 20)
#define NOBODY		65534

/* what a walk must not read: the file the mount covered */
#define SECRET	"SECRET"
#define MASK	"MASK"

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

/* Bind the loop device that LOOP_CTL_GET_FREE names to @ifd; the device number. */
static int loop_bind_free(int ifd)
{
	int cfd, lfd, n;
	char dev[32];

	cfd = open("/dev/loop-control", O_RDWR | O_CLOEXEC);
	if (cfd < 0)
		return -1;
	n = ioctl(cfd, LOOP_CTL_GET_FREE);
	close(cfd);
	if (n < 0)
		return -1;
	snprintf(dev, sizeof(dev), "/dev/loop%d", n);
	lfd = open(dev, O_RDWR | O_CLOEXEC);
	if (lfd < 0)
		return -1;
	if (ioctl(lfd, LOOP_SET_FD, ifd))
		n = -1;
	close(lfd);
	return n;
}

/* The device LOOP_CTL_GET_FREE names may be somebody else's a moment later. */
static int loop_bind(int ifd)
{
	int n = -1;

	for (int i = 0; i < 64 && n < 0; i++) {
		n = loop_bind_free(ifd);
		if (n < 0 && errno != EBUSY)
			return -1;
	}
	return n;
}

/* Tell the loop device to give its file up, now or when its last user is gone. */
static void loop_clear(int n)
{
	char dev[32];
	int lfd;

	if (n < 0)
		return;
	snprintf(dev, sizeof(dev), "/dev/loop%d", n);
	lfd = open(dev, O_RDWR | O_CLOEXEC);
	if (lfd < 0)
		return;
	ioctl(lfd, LOOP_CLR_FD);
	close(lfd);
}

FIXTURE(deleted_subvol)
{
	char base[64];		/* the tmpfs with the image and the mountpoint B */
	int loop;		/* the loop device of the image */
};

FIXTURE_SETUP(deleted_subvol)
{
	struct btrfs_ioctl_vol_args args = { .name = "sv" };
	char path[128], cmd[192];
	int ifd, bfd;

	self->loop = -1;
	if (geteuid() != 0)
		SKIP(return, "test requires root");
	if (access("/dev/loop-control", R_OK | W_OK))
		SKIP(return, "test requires loop devices");

	ASSERT_EQ(0, unshare(CLONE_NEWNS));
	ASSERT_EQ(0, mount(NULL, "/", NULL, MS_REC | MS_PRIVATE, NULL));
	strcpy(self->base, "/tmp/deleted_subvol_XXXXXX");
	ASSERT_NE(NULL, mkdtemp(self->base));
	ASSERT_EQ(0, mount("tmpfs", self->base, "tmpfs", 0, "size=512M"));

	snprintf(path, sizeof(path), "%s/image", self->base);
	ifd = open(path, O_CREAT | O_RDWR | O_CLOEXEC, 0600);
	ASSERT_GE(ifd, 0);
	ASSERT_EQ(0, ftruncate(ifd, IMAGE_SIZE));
	snprintf(cmd, sizeof(cmd), "mkfs.btrfs -q -f %s >/dev/null 2>&1", path);
	if (system(cmd)) {
		close(ifd);
		SKIP(return, "test requires mkfs.btrfs");
	}
	self->loop = loop_bind(ifd);
	close(ifd);
	ASSERT_GE(self->loop, 0);

	snprintf(path, sizeof(path), "%s/B", self->base);
	ASSERT_EQ(0, mkdir(path, 0755));
	snprintf(cmd, sizeof(cmd), "/dev/loop%d", self->loop);
	if (mount(cmd, path, "btrfs", 0, NULL)) {
		if (errno == ENODEV)
			SKIP(return, "kernel has no btrfs");
		ASSERT_EQ(0, -1) {
			TH_LOG("mounting the image: %s", strerror(errno));
		}
	}
	bfd = open(path, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
	ASSERT_GE(bfd, 0);
	ASSERT_EQ(0, ioctl(bfd, BTRFS_IOC_SUBVOL_CREATE, &args));
	close(bfd);

	snprintf(path, sizeof(path), "%s/B/sv/e", self->base);
	ASSERT_EQ(0, mkdir(path, 0755));
	snprintf(path, sizeof(path), "%s/B/sv/e/secret", self->base);
	ASSERT_EQ(0, create_file(path, SECRET));
	snprintf(cmd, sizeof(cmd), "%s/B/mask", self->base);
	ASSERT_EQ(0, create_file(cmd, MASK));
	ASSERT_EQ(0, mount(cmd, path, NULL, MS_BIND, NULL));
}

FIXTURE_TEARDOWN(deleted_subvol)
{
	char path[128];

	if (!self->base[0])
		return;
	snprintf(path, sizeof(path), "%s/B", self->base);
	umount2(path, MNT_DETACH);
	loop_clear(self->loop);
	umount2(self->base, MNT_DETACH);
	rmdir(self->base);
}

/* what a child with its cwd on sv/e sees of secret, step by step */
struct cwd_probe {
	int err[3];
	char buf[3][16];
	int unshare_err;
};

static void probe(struct cwd_probe *p, int step)
{
	int fd = open("secret", O_RDONLY | O_CLOEXEC);

	if (fd < 0) {
		p->err[step] = errno;
		return;
	}
	if (read(fd, p->buf[step], sizeof(p->buf[step]) - 1) < 0)
		p->err[step] = errno;
	close(fd);
}

/*
 * A child has its cwd on sv/e as nobody and reads MASK through the bind
 * on sv/e/secret. Then the subvolume is deleted. From then on secret is
 * ENOENT for the child, not SECRET, and its unshare(CLONE_NEWUSER |
 * CLONE_NEWNS) is refused with ENOENT. If that ever goes through, the
 * copy must not show SECRET either.
 */
TEST_F(deleted_subvol, cwd_in_a_deleted_subvolume)
{
	struct btrfs_ioctl_vol_args args = { .name = "sv" };
	int ready[2], go[2], res[2], bfd;
	char vol[128], e[128];
	struct cwd_probe p = {};
	char c = 0;
	pid_t pid;

	snprintf(vol, sizeof(vol), "%s/B", self->base);
	snprintf(e, sizeof(e), "%s/B/sv/e", self->base);
	ASSERT_EQ(0, pipe2(ready, O_CLOEXEC));
	ASSERT_EQ(0, pipe2(go, O_CLOEXEC));
	ASSERT_EQ(0, pipe2(res, O_CLOEXEC));
	pid = fork();
	ASSERT_GE(pid, 0);
	if (!pid) {
		/* nobody, with its cwd in the subvolume before it goes */
		if (setgroups(0, NULL) || setresgid(NOBODY, NOBODY, NOBODY) ||
		    setresuid(NOBODY, NOBODY, NOBODY) || chdir(e))
			_exit(1);
		probe(&p, 0);
		if (write(ready[1], &c, 1) != 1 || read(go[0], &c, 1) != 1)
			_exit(1);
		probe(&p, 1);
		if (unshare(CLONE_NEWUSER | CLONE_NEWNS))
			p.unshare_err = errno;
		else
			probe(&p, 2);
		if (write(res[1], &p, sizeof(p)) != sizeof(p))
			_exit(1);
		_exit(0);
	}
	close(ready[1]);
	close(go[0]);
	close(res[1]);
	ASSERT_EQ(1, read(ready[0], &c, 1));

	bfd = open(vol, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
	ASSERT_GE(bfd, 0);
	EXPECT_EQ(0, ioctl(bfd, BTRFS_IOC_SNAP_DESTROY, &args)) {
		TH_LOG("deleting the subvolume: %s", strerror(errno));
	}
	close(bfd);
	ASSERT_EQ(1, write(go[1], &c, 1));
	ASSERT_EQ((ssize_t)sizeof(p), read(res[0], &p, sizeof(p)));
	waitpid(pid, NULL, 0);

	EXPECT_EQ(0, p.err[0]);
	EXPECT_STREQ(MASK, p.buf[0]);
	EXPECT_EQ(ENOENT, p.err[1]) {
		TH_LOG("secret below the deleted subvolume: %s \"%s\"",
		       p.err[1] ? strerror(p.err[1]) : "opened", p.buf[1]);
	}
	EXPECT_EQ(ENOENT, p.unshare_err) {
		if (p.unshare_err)
			TH_LOG("unshare(CLONE_NEWUSER | CLONE_NEWNS) from the deleted subvolume: %s",
			       strerror(p.unshare_err));
		else
			TH_LOG("unshare(CLONE_NEWUSER | CLONE_NEWNS) from the deleted subvolume went through, secret in the copy: %s \"%s\"",
			       p.err[2] ? strerror(p.err[2]) : "opened", p.buf[2]);
	}
}

TEST_HARNESS_MAIN
