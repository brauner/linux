// SPDX-License-Identifier: GPL-2.0
#define _GNU_SOURCE
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <linux/limits.h>
#include <sched.h>
#include <stdbool.h>
#include <sys/fsuid.h>
#include <sys/sysmacros.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "internal.h"
#include "utils.h"
#include "../kselftest_harness.h"

#define IMAGE_FILE "ext4.img"
#define IMAGE_ROOT_MNT "mnt_root"
#define MNT_TARGET1 "mnt_target1"
#define FILE1 "file1"
#define FILE2 "file2"
#define DIR1 "dir1"
#define HARDLINK1 "hardlink1"
#define SYMLINK1 "symlink1"
#define CHRDEV1 "chrdev1"

static bool expected_uid_gid(int dfd, const char *path, int flags,
			     uid_t expected_uid, gid_t expected_gid)
{
	int ret;
	struct stat st;

	ret = fstatat(dfd, path, &st, flags);
	if (ret < 0)
		return false;

	return st.st_uid == expected_gid && st.st_gid == expected_gid;
}

static bool is_setid(int dfd, const char *path, int flags)
{
	int ret;
	struct stat st;

	ret = fstatat(dfd, path, &st, flags);
	if (ret < 0)
		return false;

	return (st.st_mode & S_ISUID) || (st.st_mode & S_ISGID);
}

static void call_r(const char *dirname, int (*callback)(const char *path))
{
	DIR *dir = NULL;
	struct dirent *direntp;

	dir = opendir(dirname);
	if (!dir)
		return;

	while ((direntp = readdir(dir))) {
		int ret;
		char pathname[2 * PATH_MAX];
		struct stat mystat;

		if (!strcmp(direntp->d_name, ".") ||
		    !strcmp(direntp->d_name, ".."))
			continue;

		ret = snprintf(pathname, sizeof(pathname), "%s/%s", dirname, direntp->d_name);
		if (ret < 0 || ret >= sizeof(pathname))
			continue;
		ret = lstat(pathname, &mystat);
		if (ret < 0)
			continue;

		call_r(pathname, callback);
	}

	callback(dirname);
	closedir(dir);
}

static void rm_r(const char *dirname)
{
	call_r(dirname, remove);
}

static int umount_detach(const char *path)
{
	return umount2(path, MNT_DETACH);
}

static void umount_r(const char *dirname)
{
	call_r(dirname, umount_detach);
}

static int chown_r(const char *dirname, uid_t uid, gid_t gid)
{
	int ret;
	DIR *dir = NULL;
	struct dirent *direntp;

	dir = opendir(dirname);
	if (!dir)
		return -1;

	while ((direntp = readdir(dir))) {
		char pathname[2 * PATH_MAX];

		if (!strcmp(direntp->d_name, ".") ||
		    !strcmp(direntp->d_name, ".."))
			continue;

		ret = snprintf(pathname, sizeof(pathname), "%s/%s", dirname, direntp->d_name);
		if (ret < 0 || ret >= sizeof(pathname))
			continue;
		ret = chown(pathname, uid, gid);
		if (ret < 0)
			return -1;
	}

	ret = chown(dirname, uid, gid);
	closedir(dir);
	return ret;
}

static int fd_to_fd(int from, int to)
{
	for (;;) {
		uint8_t buf[PATH_MAX];
		uint8_t *p = buf;
		ssize_t bytes_to_write;
		ssize_t bytes_read;

		bytes_read = read_nointr(from, buf, sizeof buf);
		if (bytes_read < 0)
			return -1;
		if (bytes_read == 0)
			break;

		bytes_to_write = (size_t)bytes_read;
		do {
			ssize_t bytes_written;

			bytes_written = write_nointr(to, p, bytes_to_write);
			if (bytes_written < 0)
				return -1;

			bytes_to_write -= bytes_written;
			p += bytes_written;
		} while (bytes_to_write > 0);
	}

	return 0;
}

static int sys_execveat(int fd, const char *path, char **argv, char **envp,
			int flags)
{
#ifdef __NR_execveat
	return syscall(__NR_execveat, fd, path, argv, envp, flags);
#else
	errno = ENOSYS;
	return -1;
#endif
}

FIXTURE(core) {
	int test_dir_fd;
	char test_dir_path[PATH_MAX];

	int img_fd;
	char cmdline[3 * PATH_MAX];

	int img_mnt_fd;
	int target1_fd;
	int target1_mnt_fd_attached;
	int target1_mnt_fd_detached;
};

FIXTURE_SETUP(core)
{
	struct mount_attr attr = {
		.attr_set	= 0,
		.attr_clr	= 0,
		.propagation	= MAKE_PROPAGATION_PRIVATE,
	};

	self->img_fd = -EBADF;
	self->img_mnt_fd = -EBADF;
	self->target1_fd = -EBADF;

	ASSERT_EQ(unshare(CLONE_NEWNS), 0);

	ASSERT_EQ(sys_mount_setattr(-1, "/", AT_RECURSIVE, &attr, sizeof(attr)), 0);

	snprintf(self->test_dir_path, sizeof(self->test_dir_path),
		 "/idmap_mount_core_XXXXXX");
	ASSERT_NE(mkdtemp(self->test_dir_path), NULL);
	self->test_dir_fd = open(self->test_dir_path, O_CLOEXEC | O_DIRECTORY);
	ASSERT_GE(self->test_dir_fd, 0);

	/* create filesystem image */
	self->img_fd = openat(self->test_dir_fd, IMAGE_FILE, O_CREAT | O_WRONLY, 0600);
	ASSERT_GE(self->img_fd, 0);
	ASSERT_EQ(ftruncate(self->img_fd, 640 * 1024), 0);
	snprintf(self->cmdline, sizeof(self->cmdline),
		 "mkfs.ext4 %s/" IMAGE_FILE, self->test_dir_path);
	ASSERT_EQ(system(self->cmdline), 0);

	/* create mountpoint for image */
	ASSERT_EQ(mkdirat(self->test_dir_fd, IMAGE_ROOT_MNT, 0777), 0);
	snprintf(self->cmdline, sizeof(self->cmdline),
		 "mount -o loop -t ext4 %s/" IMAGE_FILE " %s/" IMAGE_ROOT_MNT,
		 self->test_dir_path, self->test_dir_path);
	ASSERT_EQ(system(self->cmdline), 0);
	self->img_mnt_fd = openat(self->test_dir_fd, IMAGE_ROOT_MNT, O_DIRECTORY | O_CLOEXEC, 0);
	ASSERT_GE(self->img_mnt_fd, 0);

	ASSERT_EQ(mkdirat(self->test_dir_fd, MNT_TARGET1, 0777), 0);
	self->target1_fd = openat(self->test_dir_fd, MNT_TARGET1, O_DIRECTORY, 0);
	ASSERT_GE(self->target1_fd, 0);
	self->target1_mnt_fd_detached = sys_open_tree(self->test_dir_fd,
						      IMAGE_ROOT_MNT,
						      AT_NO_AUTOMOUNT |
						      AT_SYMLINK_NOFOLLOW |
						      OPEN_TREE_CLOEXEC |
						      OPEN_TREE_CLONE);
	ASSERT_GE(self->target1_mnt_fd_detached, 0);
	self->target1_mnt_fd_attached = sys_open_tree(self->test_dir_fd,
						      IMAGE_ROOT_MNT,
						      AT_NO_AUTOMOUNT |
						      AT_SYMLINK_NOFOLLOW |
						      OPEN_TREE_CLOEXEC);
	ASSERT_GE(self->target1_mnt_fd_attached, 0);
}

FIXTURE_TEARDOWN(core)
{
	EXPECT_EQ(close(self->img_fd), 0);
	EXPECT_EQ(close(self->img_mnt_fd), 0);
	EXPECT_EQ(close(self->target1_fd), 0);
	EXPECT_EQ(close(self->target1_mnt_fd_attached), 0);
	EXPECT_EQ(close(self->target1_mnt_fd_detached), 0);
	umount_r(self->test_dir_path);
	rm_r(self->test_dir_path);
	TH_LOG("Tore down test setup");
}

TEST_F(core, invalid_fd1)
{
	struct mount_attr attr = {
		.attr_set = MOUNT_ATTR_IDMAP,
	};

	/* garbage file descriptor value */
	attr.userns_fd	= -EBADF;
	ASSERT_NE(sys_mount_setattr(-1, "/", 0, &attr, sizeof(attr)), 0);
}

TEST_F(core, invalid_fd2)
{
	struct mount_attr attr = {
		.attr_set = MOUNT_ATTR_IDMAP,
	};

	/* garbage file descriptor value */
	attr.userns_fd	= INT64_MAX;
	ASSERT_NE(sys_mount_setattr(-1, "/", 0, &attr, sizeof(attr)), 0);
}

TEST_F(core, initial_user_namespace)
{
	struct mount_attr attr = {
		.attr_set = MOUNT_ATTR_IDMAP,
	};

	/* invalid user namespace */
	attr.userns_fd = open("/proc/1/ns/user", O_RDONLY | O_CLOEXEC);
	ASSERT_GE(attr.userns_fd, 0);
	ASSERT_NE(sys_mount_setattr(-1, "/", 0, &attr, sizeof(attr)), 0);
	ASSERT_EQ(errno, EPERM);
	ASSERT_EQ(close(attr.userns_fd), 0);
}

TEST_F(core, attached_mount_inside_current_mount_namespace)
{
	struct mount_attr attr = {
		.attr_set = MOUNT_ATTR_IDMAP,
	};

	/*
	 * Changing mount properties on an attached mount in our mount
	 * namespace.
	 */
	attr.userns_fd	= get_userns_fd(0, 10000, 10000);
	ASSERT_GE(attr.userns_fd, 0);
	ASSERT_EQ(sys_mount_setattr(self->target1_mnt_fd_attached, "",
				    AT_EMPTY_PATH, &attr, sizeof(attr)), 0) {
		TH_LOG("%m - Failed to idmap mount %d(%s/" MNT_TARGET1 ")",
		       self->target1_mnt_fd_attached, self->test_dir_path);
	}
	ASSERT_EQ(close(attr.userns_fd), 0);
	TH_LOG("Changed mount properties on attached mount in caller's mount namespace");
}

TEST_F(core, attached_mount_outside_current_mount_namespace)
{
	struct mount_attr attr = {
		.attr_set = MOUNT_ATTR_IDMAP,
	};

	/*
	 * Changing mount properties on a mount that is attached and not in our
	 * mount namespace must fail.
	 */
	ASSERT_EQ(unshare(CLONE_NEWNS), 0);

	attr.userns_fd	= get_userns_fd(0, 10000, 10000);
	ASSERT_GE(attr.userns_fd, 0);
	ASSERT_NE(sys_mount_setattr(self->target1_mnt_fd_attached, "",
				    AT_EMPTY_PATH, &attr, sizeof(attr)), 0) {
		TH_LOG("%m - Managed to idmap mount %d(%s/" MNT_TARGET1 ")",
		       self->target1_mnt_fd_attached, self->test_dir_path);
	}
	ASSERT_EQ(close(attr.userns_fd), 0);
	TH_LOG("Failed to change mount properties on attached mount not in caller's mount namespace");
}

TEST_F(core, detached_mount_inside_current_mount_namespace)
{
	struct mount_attr attr = {
		.attr_set = MOUNT_ATTR_IDMAP,
	};

	/* Changing mount properties on a detached mount. */
	attr.userns_fd	= get_userns_fd(0, 10000, 10000);
	ASSERT_GE(attr.userns_fd, 0);
	ASSERT_EQ(sys_mount_setattr(self->target1_mnt_fd_detached, "",
				    AT_EMPTY_PATH, &attr, sizeof(attr)), 0) {
		TH_LOG("%m - Failed to idmap mount %d(%s/" MNT_TARGET1 ")",
		       self->target1_mnt_fd_detached, self->test_dir_path);
	}
	ASSERT_EQ(close(attr.userns_fd), 0);
	TH_LOG("Changed mount properties on detached mount in caller's mount namespace");
}

TEST_F(core, detached_mount_outside_current_mount_namespace)
{
	struct mount_attr attr = {
		.attr_set = MOUNT_ATTR_IDMAP,
	};

	/*
	 * Changing mount properties on a detached mount should succeed even if
	 * it is not in our mount namespace.
	 */
	ASSERT_EQ(unshare(CLONE_NEWNS), 0);
	attr.userns_fd	= get_userns_fd(0, 10000, 10000);
	ASSERT_EQ(sys_mount_setattr(self->target1_mnt_fd_detached, "",
				    AT_EMPTY_PATH, &attr, sizeof(attr)), 0) {
		TH_LOG("%m - Failed to idmap mount %d(%s/" MNT_TARGET1 ")",
		       self->target1_mnt_fd_detached, self->test_dir_path);
	}
	ASSERT_EQ(close(attr.userns_fd), 0);
	TH_LOG("Changed mount properties on detached mount not in caller's mount namespace");
}

TEST_F(core, change_idmapping)
{
	struct mount_attr attr = {
		.attr_set = MOUNT_ATTR_IDMAP,
	};

	/* Changing mount properties on a detached mount. */
	attr.userns_fd	= get_userns_fd(0, 10000, 10000);
	ASSERT_GE(attr.userns_fd, 0);
	ASSERT_EQ(sys_mount_setattr(self->target1_mnt_fd_detached, "",
				    AT_EMPTY_PATH, &attr, sizeof(attr)), 0) {
		TH_LOG("%m - Failed to idmap mount %d(%s/" MNT_TARGET1 ")",
		       self->target1_mnt_fd_detached, self->test_dir_path);
	}
	ASSERT_EQ(close(attr.userns_fd), 0);
	TH_LOG("Changed mount properties on detached mount in caller's mount namespace");

	/* Change idmapping on a detached mount that is already idmapped. */
	attr.userns_fd	= get_userns_fd(0, 20000, 10000);
	ASSERT_GE(attr.userns_fd, 0);
	ASSERT_EQ(sys_mount_setattr(self->target1_mnt_fd_detached, "",
				    AT_EMPTY_PATH, &attr, sizeof(attr)), 0) {
		TH_LOG("%m - Failed to idmap mount %d(%s/" MNT_TARGET1 ")",
		       self->target1_mnt_fd_detached, self->test_dir_path);
	}
	ASSERT_EQ(close(attr.userns_fd), 0);
	TH_LOG("Changed mount properties on detached mount in caller's mount namespace");

	ASSERT_EQ(sys_move_mount(self->target1_mnt_fd_detached, "",
				 self->test_dir_fd, MNT_TARGET1, MOVE_MOUNT_F_EMPTY_PATH), 0) {
		TH_LOG("%m - Failed to attached detached mount %d(%s/" IMAGE_FILE ") to %s/" MNT_TARGET1,
		       self->target1_mnt_fd_detached, self->test_dir_path,
		       self->test_dir_path);
	}
	TH_LOG("Attached detached mount %d(%s/" IMAGE_FILE ") to %s/" MNT_TARGET1,
	       self->target1_mnt_fd_detached, self->test_dir_path,
	       self->test_dir_path);

	/* Change idmapping on an attached mount that is already idmapped. */
	attr.userns_fd	= get_userns_fd(0, 30000, 10000);
	ASSERT_GE(attr.userns_fd, 0);
	ASSERT_NE(sys_mount_setattr(self->target1_mnt_fd_detached, "",
				    AT_EMPTY_PATH, &attr, sizeof(attr)), 0);
	ASSERT_EQ(close(attr.userns_fd), 0);
	TH_LOG("Failed to change mount properties on attached mount in caller's mount namespace");
}

TEST_F(core, expected_uid_gid)
{
	int file1_fd = -EBADF;
	uid_t fsuid;
	gid_t fsgid;
	struct mount_attr attr = {
		.attr_set = MOUNT_ATTR_IDMAP,
	};

	file1_fd = openat(self->img_mnt_fd, FILE1, O_CREAT | O_EXCL | O_CLOEXEC, 0644);
	ASSERT_GE(file1_fd, 0);

	ASSERT_EQ(mknodat(self->img_mnt_fd, FILE2, S_IFREG | 0000, 0), 0);

	ASSERT_EQ(mknodat(self->img_mnt_fd, CHRDEV1, S_IFCHR | 0644,
			  makedev(5, 1)), 0);

	ASSERT_EQ(linkat(self->img_mnt_fd, FILE1, self->img_mnt_fd, HARDLINK1, 0), 0);

	ASSERT_EQ(symlinkat(FILE2, self->img_mnt_fd, SYMLINK1), 0);

	ASSERT_EQ(mkdirat(self->img_mnt_fd, DIR1, 0700), 0);

	fsuid = setfsuid(-1);
	fsgid = setfsgid(-1);

	/* Changing mount properties on a detached mount. */
	attr.userns_fd	= get_userns_fd(0, 10000, 10000);
	ASSERT_GE(attr.userns_fd, 0);
	ASSERT_EQ(sys_mount_setattr(self->target1_mnt_fd_detached, "",
				    AT_EMPTY_PATH, &attr, sizeof(attr)), 0) {
		TH_LOG("%m - Failed to idmap mount %d(%s/" MNT_TARGET1 ")",
		       self->target1_mnt_fd_detached, self->test_dir_path);
	}
	ASSERT_EQ(close(attr.userns_fd), 0);
	TH_LOG("Changed mount properties on detached mount in caller's mount namespace");

	/*
	 * All files created through the original image mountpoint  are owned
	 * by uid 0.
	 */
	ASSERT_EQ(expected_uid_gid(self->img_mnt_fd, FILE1,
		  0, fsuid, fsgid), true);

	ASSERT_EQ(expected_uid_gid(self->img_mnt_fd, FILE2,
		  0, fsuid, fsgid), true);

	ASSERT_EQ(expected_uid_gid(self->img_mnt_fd, HARDLINK1,
		  0, fsuid, fsgid), true);

	ASSERT_EQ(expected_uid_gid(self->img_mnt_fd, CHRDEV1,
		  0, fsuid, fsgid), true);

	ASSERT_EQ(expected_uid_gid(self->img_mnt_fd, SYMLINK1,
		  0, fsuid, fsgid), true);

	ASSERT_EQ(expected_uid_gid(self->img_mnt_fd, DIR1,
		  0, fsuid, fsgid), true);

	/*
	 * All files are owned by uid 10000 if accessed through the idmapped
	 * mountpoint.
	 */
	ASSERT_EQ(expected_uid_gid(self->target1_mnt_fd_detached, FILE1,
		  0, 10000, 10000), true);

	ASSERT_EQ(expected_uid_gid(self->target1_mnt_fd_detached, FILE2,
		  0, 10000, 10000), true);

	ASSERT_EQ(expected_uid_gid(self->target1_mnt_fd_detached, HARDLINK1,
		  0, 10000, 10000), true);

	ASSERT_EQ(expected_uid_gid(self->target1_mnt_fd_detached, CHRDEV1,
		  0, 10000, 10000), true);

	ASSERT_EQ(expected_uid_gid(self->target1_mnt_fd_detached, SYMLINK1,
		  0, 10000, 10000), true);

	ASSERT_EQ(expected_uid_gid(self->target1_mnt_fd_detached, DIR1,
		  0, 10000, 10000), true);

	/* Change ownership throught original image mountpoint. */
	ASSERT_EQ(fchownat(self->img_mnt_fd, FILE1, 1000, 1000, 0), 0);

	/* Verify correct ownership through original image mountpoint. */
	ASSERT_EQ(expected_uid_gid(self->img_mnt_fd, FILE1,
		  0, 1000, 1000), true);

	ASSERT_EQ(expected_uid_gid(self->img_mnt_fd, HARDLINK1,
		  0, 1000, 1000), true);

	/* Verify correct ownership through idmapped mountpoint. */
	ASSERT_EQ(expected_uid_gid(self->target1_mnt_fd_detached, FILE1,
		  0, 11000, 11000), true);

	ASSERT_EQ(expected_uid_gid(self->target1_mnt_fd_detached, HARDLINK1,
		  0, 11000, 11000), true);

	/* Change ownership throught idmapped mountpoint. */
	ASSERT_EQ(fchownat(self->target1_mnt_fd_detached, DIR1,
			   11000, 11000, 0), 0);

	/* Verify correct ownership through original image mountpoint. */
	ASSERT_EQ(expected_uid_gid(self->img_mnt_fd, DIR1,
		  0, 1000, 1000), true);

	/* Verify correct ownership through idmapped mountpoint. */
	ASSERT_EQ(expected_uid_gid(self->target1_mnt_fd_detached, DIR1,
		  0, 11000, 11000), true);

	/* Change idmapping on a detached mount that is already idmapped. */
	attr.userns_fd	= get_userns_fd(0, 20000, 10000);
	ASSERT_GE(attr.userns_fd, 0);
	ASSERT_EQ(sys_mount_setattr(self->target1_mnt_fd_detached, "",
				    AT_EMPTY_PATH, &attr, sizeof(attr)), 0) {
		TH_LOG("%m - Failed to idmap mount %d(%s/" MNT_TARGET1 ")",
		       self->target1_mnt_fd_detached, self->test_dir_path);
	}
	ASSERT_EQ(close(attr.userns_fd), 0);
	TH_LOG("Changed mount properties on detached mount in caller's mount namespace");

	ASSERT_EQ(expected_uid_gid(self->target1_mnt_fd_detached, FILE1,
		  0, 21000, 21000), true);

	ASSERT_EQ(expected_uid_gid(self->target1_mnt_fd_detached, HARDLINK1,
		  0, 21000, 21000), true);

	ASSERT_EQ(expected_uid_gid(self->target1_mnt_fd_detached, FILE2,
		  0, 20000, 20000), true);

	ASSERT_EQ(expected_uid_gid(self->target1_mnt_fd_detached, CHRDEV1,
		  0, 20000, 20000), true);

	ASSERT_EQ(expected_uid_gid(self->target1_mnt_fd_detached, SYMLINK1,
		  0, 20000, 20000), true);

	ASSERT_EQ(expected_uid_gid(self->target1_mnt_fd_detached, DIR1,
		  0, 21000, 21000), true);

	// /* Shift ownership to unprivileged ids. */
	// ASSERT_EQ(chown_r(self->img_mnt_fd, 20000, 20000), 0);

	// attr.userns_fd	= get_userns_fd(20000, 0, 10000);
	// ASSERT_GE(attr.userns_fd, 0);
	// ASSERT_EQ(sys_mount_setattr(self->target1_mnt_fd_detached, "",
	// 			    AT_EMPTY_PATH, &attr, sizeof(attr)), 0) {
	// 	TH_LOG("%m - Failed to idmap mount %d(%s/" MNT_TARGET1 ")",
	// 	       self->target1_mnt_fd_detached, self->test_dir_path);
	// }
	// ASSERT_EQ(close(attr.userns_fd), 0);
	// TH_LOG("Changed mount properties on detached mount in caller's mount namespace");

	ASSERT_EQ(close(file1_fd), 0);
}

TEST_F(core, setid_binaries)
{
	int ret;
	int file1_fd = -EBADF, exec_fd = -EBADF;
	pid_t pid;

	struct mount_attr attr = {
		.attr_set = MOUNT_ATTR_IDMAP,
	};

	/* Create setuid binary. */
	file1_fd = openat(self->img_mnt_fd, FILE1, O_CREAT | O_EXCL | O_RDWR | O_CLOEXEC, 0644);
	ASSERT_GE(file1_fd, 0);

	exec_fd = openat(-EBADF, "/proc/self/exe", O_RDONLY | O_CLOEXEC, 0000);
	ASSERT_GE(exec_fd, 0);

	ASSERT_EQ(fd_to_fd(exec_fd, file1_fd), 0);
	ASSERT_EQ(fchown(file1_fd, 0, 0), 0);
	ASSERT_EQ(fchmod(file1_fd, S_IXUSR | S_IXGRP | S_IXOTH | S_IEXEC | S_ISUID | S_ISGID), 0);
	ASSERT_EQ(close(exec_fd), 0);
	ASSERT_EQ(close(file1_fd), 0);

	/* Changing mount properties on a detached mount. */
	attr.userns_fd	= get_userns_fd(0, 10000, 10000);
	ASSERT_GE(attr.userns_fd, 0);
	ASSERT_EQ(sys_mount_setattr(self->target1_mnt_fd_detached, "",
				    AT_EMPTY_PATH, &attr, sizeof(attr)), 0) {
		TH_LOG("%m - Failed to idmap mount %d(%s/" MNT_TARGET1 ")",
		       self->target1_mnt_fd_detached, self->test_dir_path);
	}
	ASSERT_EQ(close(attr.userns_fd), 0);
	TH_LOG("Changed mount properties on detached mount in caller's mount namespace");

	/* Verify we run setid binary as uid and gid 0 from original image mount. */
	pid = fork();
	ASSERT_GE(pid, 0);
	if (pid == 0) {
		static char *envp[] = { "EXPECTED_UID=0", "EXPECTED_GID=0", NULL, };
		static char *argv[] = {  NULL, };
		ASSERT_EQ(setresgid(100000, 100000, 100000), 0);
		ASSERT_EQ(setresuid(100000, 100000, 100000), 0);
		ASSERT_EQ(sys_execveat(self->img_mnt_fd, FILE1, argv, envp, 0), 0) {
			TH_LOG("%m - Failed to execute setuid binary");
		}

		exit(EXIT_FAILURE);
	}

	ret = wait_for_pid(pid);
	ASSERT_EQ(ret, 0);

	/*
	 * A detached mount will have an anonymous mount namespace attached to
	 * it. This means that we can't execute setid binaries on a detached
	 * mount because the mnt_may_suid() helper will fail the check_mount()
	 * part of its check which compares the caller's mount namespace to the
	 * detached mount's mount namespace. Since by definition an anonymous
	 * mount namespace is not equale to any mount namespace currently in
	 * use this can't work. So attach the mount to the filesystem first
	 * before performing this check.
	 */
	ASSERT_EQ(sys_move_mount(self->target1_mnt_fd_detached, "",
				 self->test_dir_fd, MNT_TARGET1,
				 MOVE_MOUNT_F_EMPTY_PATH), 0) {
		TH_LOG("%m - Failed to attached detached mount %d(%s/" IMAGE_FILE ") to %s/" MNT_TARGET1,
		       self->target1_mnt_fd_detached, self->test_dir_path,
		       self->test_dir_path);
	}
	TH_LOG("Attached detached mount %d(%s/" IMAGE_FILE ") to %s/" MNT_TARGET1,
	       self->target1_mnt_fd_detached, self->test_dir_path,
	       self->test_dir_path);

	/* Verify we run setid binary as uid and gid 10000 from idmapped mount mount. */
	pid = fork();
	ASSERT_GE(pid, 0);
	if (pid == 0) {
		static char *envp[] = { "EXPECTED_UID=10000", "EXPECTED_GID=10000", NULL, };
		static char *argv[] = {  NULL, };
		ASSERT_EQ(expected_uid_gid(self->target1_mnt_fd_detached, FILE1, 0, 10000, 10000), true);
		ASSERT_EQ(setresgid(100000, 100000, 100000), 0);
		ASSERT_EQ(setresuid(100000, 100000, 100000), 0);
		ASSERT_EQ(sys_execveat(self->target1_mnt_fd_detached, FILE1, argv, envp, 0), 0) {
			TH_LOG("%m - Failed to execute setuid binary");
		}

		exit(EXIT_FAILURE);
	}

	ret = wait_for_pid(pid);
	ASSERT_EQ(ret, 0);

	/* Unmount the current idmapped mount. */
	snprintf(self->cmdline, sizeof(self->cmdline), "%s/" MNT_TARGET1, self->test_dir_path);
	ASSERT_EQ(umount2(self->cmdline, MNT_DETACH), 0);

	/* Chown all files to an unprivileged user. */
	snprintf(self->cmdline, sizeof(self->cmdline), "%s/" IMAGE_ROOT_MNT, self->test_dir_path);
	ASSERT_EQ(chown_r(self->cmdline, 10000, 10000), 0);

	/* Verify that the sid bits got cleared after changing ownership. */
	ASSERT_EQ(is_setid(self->img_mnt_fd, FILE1, 0), false);

	/* Set setid bits on the newly chowned binary. */
	ASSERT_EQ(fchmodat(self->img_mnt_fd, FILE1, S_IXUSR | S_IXGRP | S_IXOTH | S_IEXEC | S_ISUID | S_ISGID, 0), 0);

	/* Verify that the sid bits got raised. */
	ASSERT_EQ(is_setid(self->img_mnt_fd, FILE1, 0), true);

	/* Changing mount properties on a detached mount. */
	attr.userns_fd	= get_userns_fd(10000, 0, 10000);
	ASSERT_GE(attr.userns_fd, 0);
	ASSERT_EQ(sys_mount_setattr(self->target1_mnt_fd_detached, "",
				    AT_EMPTY_PATH, &attr, sizeof(attr)), 0) {
		TH_LOG("%m - Failed to idmap mount %d(%s/" MNT_TARGET1 ")",
		       self->target1_mnt_fd_detached, self->test_dir_path);
	}
	ASSERT_EQ(close(attr.userns_fd), 0);
	TH_LOG("Changed mount properties on detached mount in caller's mount namespace");

	/* Attach the mount to the filesystem. */
	ASSERT_EQ(sys_move_mount(self->target1_mnt_fd_detached, "",
				 self->test_dir_fd, MNT_TARGET1,
				 MOVE_MOUNT_F_EMPTY_PATH), 0) {
		TH_LOG("%m - Failed to attached detached mount %d(%s/" IMAGE_FILE ") to %s/" MNT_TARGET1,
		       self->target1_mnt_fd_detached, self->test_dir_path,
		       self->test_dir_path);
	}
	TH_LOG("Attached detached mount %d(%s/" IMAGE_FILE ") to %s/" MNT_TARGET1,
	       self->target1_mnt_fd_detached, self->test_dir_path,
	       self->test_dir_path);

	/* Verify we run setid binary as uid and gid 0 from idmapped mount mount. */
	pid = fork();
	ASSERT_GE(pid, 0);
	if (pid == 0) {
		static char *envp[] = { "EXPECTED_UID=0", "EXPECTED_GID=0", NULL, };
		static char *argv[] = {  NULL, };
		ASSERT_EQ(expected_uid_gid(self->target1_mnt_fd_detached, FILE1, 0, 10000, 10000), true);
		ASSERT_EQ(setresgid(100000, 100000, 100000), 0);
		ASSERT_EQ(setresuid(100000, 100000, 100000), 0);
		ASSERT_EQ(sys_execveat(self->target1_mnt_fd_detached, FILE1, argv, envp, 0), 0) {
			TH_LOG("%m - Failed to execute setuid binary");
		}

		exit(EXIT_FAILURE);
	}

	ret = wait_for_pid(pid);
	ASSERT_EQ(ret, 0);

	/* Verify we run setid binary as uid and gid 10000 from original image mount. */
	pid = fork();
	ASSERT_GE(pid, 0);
	if (pid == 0) {
		static char *envp[] = { "EXPECTED_UID=10000", "EXPECTED_GID=10000", NULL, };
		static char *argv[] = {  NULL, };
		ASSERT_EQ(setresgid(100000, 100000, 100000), 0);
		ASSERT_EQ(setresuid(100000, 100000, 100000), 0);
		ASSERT_EQ(sys_execveat(self->img_mnt_fd, FILE1, argv, envp, 0), 0) {
			TH_LOG("%m - Failed to execute setuid binary");
		}

		exit(EXIT_FAILURE);
	}

	ret = wait_for_pid(pid);
	ASSERT_EQ(ret, 0);
}

// TEST_F(core, idmap_mount_tree)
// {
// 	struct mount_attr attr = {
// 		.attr_set	= MOUNT_ATTR_IDMAP,
// 		.userns_fd	= get_userns_fd(0, 10000, 10000),
// 	};
//
// 	ASSERT_EQ(sys_mount_setattr(-1, "/", AT_RECURSIVE, &attr, sizeof(attr)), 0);
// }

static void __attribute__((constructor)) setuid_rexec(void)
{
	const char *expected_uid_str, *expected_gid_str;
	uid_t expected_uid;
	gid_t expected_gid;

	expected_uid_str = getenv("EXPECTED_UID");
	expected_gid_str = getenv("EXPECTED_GID");

	if (expected_uid_str && expected_gid_str) {
		expected_uid = atoi(expected_uid_str);
		expected_gid = atoi(expected_gid_str);

		fprintf(stderr, "expected_uid(%d) | getuid(%d) | geteuid(%d)\n", expected_uid, getuid(), geteuid());
		fprintf(stderr, "expected_gid(%d) | getgid(%d) | getegid(%d)\n", expected_gid, getgid(), getegid());

		if ((getuid() == geteuid()) || (expected_uid != geteuid()))
			exit(EXIT_FAILURE);

		if ((getgid() == getegid()) || (expected_gid != getegid()))
			exit(EXIT_FAILURE);

		exit(EXIT_SUCCESS);
	}
}

TEST_HARNESS_MAIN
