// SPDX-License-Identifier: GPL-2.0

#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <linux/types.h>
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syscall.h>
#include <sys/prctl.h>
#include <sys/wait.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/stat.h>

#include "pidfd.h"
#include "kselftest_harness.h"

#ifndef SETNS_ALL
#define SETNS_ALL 0x00000001
#endif

enum {
	PIDFD_NS_USER,
	PIDFD_NS_MNT,
	PIDFD_NS_PID,
	PIDFD_NS_UTS,
	PIDFD_NS_IPC,
	PIDFD_NS_NET,
	PIDFD_NS_CGROUP,
	PIDFD_NS_PIDCLD,
	PIDFD_NS_TIME,
	PIDFD_NS_TIMECLD,
	PIDFD_NS_MAX
};

const struct ns_info {
	const char *name;
	int flag;
	unsigned int pidfd_ioctl;
} ns_info[] = {
	[PIDFD_NS_USER]    = { "user",              CLONE_NEWUSER,   PIDFD_GET_USER_NAMESPACE,              },
	[PIDFD_NS_MNT]     = { "mnt",               CLONE_NEWNS,     PIDFD_GET_MNT_NAMESPACE,               },
	[PIDFD_NS_PID]     = { "pid",               CLONE_NEWPID,    PIDFD_GET_PID_NAMESPACE,               },
	[PIDFD_NS_UTS]     = { "uts",               CLONE_NEWUTS,    PIDFD_GET_UTS_NAMESPACE,               },
	[PIDFD_NS_IPC]     = { "ipc",               CLONE_NEWIPC,    PIDFD_GET_IPC_NAMESPACE,               },
	[PIDFD_NS_NET]     = { "net",               CLONE_NEWNET,    PIDFD_GET_NET_NAMESPACE,               },
	[PIDFD_NS_CGROUP]  = { "cgroup",            CLONE_NEWCGROUP, PIDFD_GET_CGROUP_NAMESPACE,            },
	[PIDFD_NS_TIME]	   = { "time",              CLONE_NEWTIME,   PIDFD_GET_TIME_NAMESPACE,              },
	[PIDFD_NS_PIDCLD]  = { "pid_for_children",  0,               PIDFD_GET_PID_FOR_CHILDREN_NAMESPACE,  },
	[PIDFD_NS_TIMECLD] = { "time_for_children", 0,               PIDFD_GET_TIME_FOR_CHILDREN_NAMESPACE, },
};

FIXTURE(current_nsset)
{
	pid_t pid;
	int pidfd;
	int nsfds[PIDFD_NS_MAX];
	int child_pidfd_derived_nsfds[PIDFD_NS_MAX];

	pid_t child_pid_exited;
	int child_pidfd_exited;

	pid_t child_pid1;
	int child_pidfd1;
	int child_nsfds1[PIDFD_NS_MAX];
	int child_pidfd_derived_nsfds1[PIDFD_NS_MAX];

	pid_t child_pid2;
	int child_pidfd2;
	int child_nsfds2[PIDFD_NS_MAX];
	int child_pidfd_derived_nsfds2[PIDFD_NS_MAX];
};

static bool switch_timens(void)
{
	int fd, ret;

	if (unshare(CLONE_NEWTIME))
		return false;

	fd = open("/proc/self/ns/time_for_children", O_RDONLY | O_CLOEXEC);
	if (fd < 0)
		return false;

	ret = setns(fd, CLONE_NEWTIME);
	close(fd);
	return ret == 0;
}

FIXTURE_SETUP(current_nsset)
{
	int i, proc_fd, ret;
	int ipc_sockets[2];
	char c;

	for (i = 0; i < PIDFD_NS_MAX; i++) {
		self->nsfds[i]				= -EBADF;
		self->child_nsfds1[i]			= -EBADF;
		self->child_nsfds2[i]			= -EBADF;
		self->child_pidfd_derived_nsfds[i]	= -EBADF;
		self->child_pidfd_derived_nsfds1[i]	= -EBADF;
		self->child_pidfd_derived_nsfds2[i]	= -EBADF;
	}

	proc_fd = open("/proc/self/ns", O_DIRECTORY | O_CLOEXEC);
	ASSERT_GE(proc_fd, 0) {
		TH_LOG("%m - Failed to open /proc/self/ns");
	}

	self->pid = getpid();
	self->pidfd = sys_pidfd_open(self->pid, 0);
	EXPECT_GT(self->pidfd, 0) {
		TH_LOG("%m - Failed to open pidfd for process %d", self->pid);
	}

	for (i = 0; i < PIDFD_NS_MAX; i++) {
		const struct ns_info *info = &ns_info[i];
		self->nsfds[i] = openat(proc_fd, info->name, O_RDONLY | O_CLOEXEC);
		if (self->nsfds[i] < 0) {
			EXPECT_EQ(errno, ENOENT) {
				TH_LOG("%m - Failed to open %s namespace for process %d",
				       info->name, self->pid);
			}
		}

		self->child_pidfd_derived_nsfds[i] = ioctl(self->pidfd, info->pidfd_ioctl, 0);
		if (self->child_pidfd_derived_nsfds[i] < 0) {
			EXPECT_EQ(errno, EOPNOTSUPP) {
				TH_LOG("%m - Failed to derive %s namespace from pidfd of process %d",
				       info->name, self->pid);
			}
		}
	}

	/* Create task that exits right away. */
	self->child_pid_exited = create_child(&self->child_pidfd_exited, 0);
	EXPECT_GE(self->child_pid_exited, 0);

	if (self->child_pid_exited == 0) {
		if (self->nsfds[PIDFD_NS_USER] >= 0 && unshare(CLONE_NEWUSER) < 0)
			_exit(EXIT_FAILURE);
		if (self->nsfds[PIDFD_NS_NET] >= 0 && unshare(CLONE_NEWNET) < 0)
			_exit(EXIT_FAILURE);
		_exit(EXIT_SUCCESS);
	}

	ASSERT_EQ(sys_waitid(P_PID, self->child_pid_exited, NULL, WEXITED | WNOWAIT), 0);

	self->pidfd = sys_pidfd_open(self->pid, 0);
	EXPECT_GE(self->pidfd, 0) {
		TH_LOG("%m - Failed to open pidfd for process %d", self->pid);
	}

	ret = socketpair(AF_LOCAL, SOCK_STREAM | SOCK_CLOEXEC, 0, ipc_sockets);
	EXPECT_EQ(ret, 0);

	/* Create tasks that will be stopped. */
	if (self->nsfds[PIDFD_NS_USER] >= 0 && self->nsfds[PIDFD_NS_PID] >= 0)
		self->child_pid1 = create_child(&self->child_pidfd1, CLONE_NEWUSER | CLONE_NEWPID);
	else if (self->nsfds[PIDFD_NS_PID] >= 0)
		self->child_pid1 = create_child(&self->child_pidfd1, CLONE_NEWPID);
	else if (self->nsfds[PIDFD_NS_USER] >= 0)
		self->child_pid1 = create_child(&self->child_pidfd1, CLONE_NEWUSER);
	else
		self->child_pid1 = create_child(&self->child_pidfd1, 0);
	EXPECT_GE(self->child_pid1, 0);

	if (self->child_pid1 == 0) {
		close(ipc_sockets[0]);

		if (self->nsfds[PIDFD_NS_MNT] >= 0 && unshare(CLONE_NEWNS) < 0) {
			TH_LOG("%m - Failed to unshare mount namespace for process %d", self->pid);
			_exit(EXIT_FAILURE);
		}
		if (self->nsfds[PIDFD_NS_CGROUP] >= 0 && unshare(CLONE_NEWCGROUP) < 0) {
			TH_LOG("%m - Failed to unshare cgroup namespace for process %d", self->pid);
			_exit(EXIT_FAILURE);
		}
		if (self->nsfds[PIDFD_NS_IPC] >= 0 && unshare(CLONE_NEWIPC) < 0) {
			TH_LOG("%m - Failed to unshare ipc namespace for process %d", self->pid);
			_exit(EXIT_FAILURE);
		}
		if (self->nsfds[PIDFD_NS_UTS] >= 0 && unshare(CLONE_NEWUTS) < 0) {
			TH_LOG("%m - Failed to unshare uts namespace for process %d", self->pid);
			_exit(EXIT_FAILURE);
		}
		if (self->nsfds[PIDFD_NS_NET] >= 0 && unshare(CLONE_NEWNET) < 0) {
			TH_LOG("%m - Failed to unshare net namespace for process %d", self->pid);
			_exit(EXIT_FAILURE);
		}
		if (self->nsfds[PIDFD_NS_TIME] >= 0 && !switch_timens()) {
			TH_LOG("%m - Failed to unshare time namespace for process %d", self->pid);
			_exit(EXIT_FAILURE);
		}

		if (write_nointr(ipc_sockets[1], "1", 1) < 0)
			_exit(EXIT_FAILURE);

		close(ipc_sockets[1]);

		pause();
		_exit(EXIT_SUCCESS);
	}

	close(ipc_sockets[1]);
	ASSERT_EQ(read_nointr(ipc_sockets[0], &c, 1), 1);
	close(ipc_sockets[0]);

	ret = socketpair(AF_LOCAL, SOCK_STREAM | SOCK_CLOEXEC, 0, ipc_sockets);
	EXPECT_EQ(ret, 0);

	if (self->nsfds[PIDFD_NS_USER] >= 0 && self->nsfds[PIDFD_NS_PID] >= 0)
		self->child_pid2 = create_child(&self->child_pidfd2, CLONE_NEWUSER | CLONE_NEWPID);
	else if (self->nsfds[PIDFD_NS_PID] >= 0)
		self->child_pid2 = create_child(&self->child_pidfd2, CLONE_NEWPID);
	else if (self->nsfds[PIDFD_NS_USER] >= 0)
		self->child_pid2 = create_child(&self->child_pidfd2, CLONE_NEWUSER);
	else
		self->child_pid2 = create_child(&self->child_pidfd2, 0);
	EXPECT_GE(self->child_pid2, 0);

	if (self->child_pid2 == 0) {
		close(ipc_sockets[0]);

		if (self->nsfds[PIDFD_NS_MNT] >= 0 && unshare(CLONE_NEWNS) < 0) {
			TH_LOG("%m - Failed to unshare mount namespace for process %d", self->pid);
			_exit(EXIT_FAILURE);
		}
		if (self->nsfds[PIDFD_NS_CGROUP] >= 0 && unshare(CLONE_NEWCGROUP) < 0) {
			TH_LOG("%m - Failed to unshare cgroup namespace for process %d", self->pid);
			_exit(EXIT_FAILURE);
		}
		if (self->nsfds[PIDFD_NS_IPC] >= 0 && unshare(CLONE_NEWIPC) < 0) {
			TH_LOG("%m - Failed to unshare ipc namespace for process %d", self->pid);
			_exit(EXIT_FAILURE);
		}
		if (self->nsfds[PIDFD_NS_UTS] >= 0 && unshare(CLONE_NEWUTS) < 0) {
			TH_LOG("%m - Failed to unshare uts namespace for process %d", self->pid);
			_exit(EXIT_FAILURE);
		}
		if (self->nsfds[PIDFD_NS_NET] >= 0 && unshare(CLONE_NEWNET) < 0) {
			TH_LOG("%m - Failed to unshare net namespace for process %d", self->pid);
			_exit(EXIT_FAILURE);
		}
		if (self->nsfds[PIDFD_NS_TIME] >= 0 && !switch_timens()) {
			TH_LOG("%m - Failed to unshare time namespace for process %d", self->pid);
			_exit(EXIT_FAILURE);
		}

		if (write_nointr(ipc_sockets[1], "1", 1) < 0)
			_exit(EXIT_FAILURE);

		close(ipc_sockets[1]);

		pause();
		_exit(EXIT_SUCCESS);
	}

	close(ipc_sockets[1]);
	ASSERT_EQ(read_nointr(ipc_sockets[0], &c, 1), 1);
	close(ipc_sockets[0]);

	for (i = 0; i < PIDFD_NS_MAX; i++) {
		char p[100];

		const struct ns_info *info = &ns_info[i];

		self->nsfds[i] = openat(proc_fd, info->name, O_RDONLY | O_CLOEXEC);
		if (self->nsfds[i] < 0) {
			EXPECT_EQ(errno, ENOENT) {
				TH_LOG("%m - Failed to open %s namespace for process %d",
				       info->name, self->pid);
			}
		}

		ret = snprintf(p, sizeof(p), "/proc/%d/ns/%s",
			       self->child_pid1, info->name);
		EXPECT_GT(ret, 0);
		EXPECT_LT(ret, sizeof(p));

		self->child_nsfds1[i] = open(p, O_RDONLY | O_CLOEXEC);
		if (self->child_nsfds1[i] < 0) {
			EXPECT_EQ(errno, ENOENT) {
				TH_LOG("%m - Failed to open %s namespace for process %d",
				       info->name, self->child_pid1);
			}
		}

		ret = snprintf(p, sizeof(p), "/proc/%d/ns/%s",
			       self->child_pid2, info->name);
		EXPECT_GT(ret, 0);
		EXPECT_LT(ret, sizeof(p));

		self->child_nsfds2[i] = open(p, O_RDONLY | O_CLOEXEC);
		if (self->child_nsfds2[i] < 0) {
			EXPECT_EQ(errno, ENOENT) {
				TH_LOG("%m - Failed to open %s namespace for process %d",
				       info->name, self->child_pid1);
			}
		}

		self->child_pidfd_derived_nsfds1[i] = ioctl(self->child_pidfd1, info->pidfd_ioctl, 0);
		if (self->child_pidfd_derived_nsfds1[i] < 0) {
			EXPECT_EQ(errno, EOPNOTSUPP) {
				TH_LOG("%m - Failed to derive %s namespace from pidfd of process %d",
				       info->name, self->child_pid1);
			}
		}

		self->child_pidfd_derived_nsfds2[i] = ioctl(self->child_pidfd2, info->pidfd_ioctl, 0);
		if (self->child_pidfd_derived_nsfds2[i] < 0) {
			EXPECT_EQ(errno, EOPNOTSUPP) {
				TH_LOG("%m - Failed to derive %s namespace from pidfd of process %d",
				       info->name, self->child_pid2);
			}
		}
	}

	close(proc_fd);
}

FIXTURE_TEARDOWN(current_nsset)
{
	int i;

	ASSERT_EQ(sys_pidfd_send_signal(self->child_pidfd1,
					SIGKILL, NULL, 0), 0);
	ASSERT_EQ(sys_pidfd_send_signal(self->child_pidfd2,
					SIGKILL, NULL, 0), 0);

	for (i = 0; i < PIDFD_NS_MAX; i++) {
		if (self->nsfds[i] >= 0)
			close(self->nsfds[i]);
		if (self->child_nsfds1[i] >= 0)
			close(self->child_nsfds1[i]);
		if (self->child_nsfds2[i] >= 0)
			close(self->child_nsfds2[i]);
		if (self->child_pidfd_derived_nsfds[i] >= 0)
			close(self->child_pidfd_derived_nsfds[i]);
		if (self->child_pidfd_derived_nsfds1[i] >= 0)
			close(self->child_pidfd_derived_nsfds1[i]);
		if (self->child_pidfd_derived_nsfds2[i] >= 0)
			close(self->child_pidfd_derived_nsfds2[i]);
	}

	if (self->child_pidfd1 >= 0)
		EXPECT_EQ(0, close(self->child_pidfd1));
	if (self->child_pidfd2 >= 0)
		EXPECT_EQ(0, close(self->child_pidfd2));
	ASSERT_EQ(sys_waitid(P_PID, self->child_pid_exited, NULL, WEXITED), 0);
	ASSERT_EQ(sys_waitid(P_PID, self->child_pid1, NULL, WEXITED), 0);
	ASSERT_EQ(sys_waitid(P_PID, self->child_pid2, NULL, WEXITED), 0);
}

static int preserve_ns(const int pid, const char *ns)
{
	int ret;
	char path[50];

	ret = snprintf(path, sizeof(path), "/proc/%d/ns/%s", pid, ns);
	if (ret < 0 || (size_t)ret >= sizeof(path))
		return -EIO;

	return open(path, O_RDONLY | O_CLOEXEC);
}

static int in_same_namespace(int ns_fd1, pid_t pid2, const char *ns)
{
	int ns_fd2 = -EBADF;
	int ret = -1;
	struct stat ns_st1, ns_st2;

	ret = fstat(ns_fd1, &ns_st1);
	if (ret < 0)
		return -1;

	ns_fd2 = preserve_ns(pid2, ns);
	if (ns_fd2 < 0)
		return -1;

	ret = fstat(ns_fd2, &ns_st2);
	close(ns_fd2);
	if (ret < 0)
		return -1;

	/* processes are in the same namespace */
	if ((ns_st1.st_dev == ns_st2.st_dev) &&
	    (ns_st1.st_ino == ns_st2.st_ino))
		return 1;

	/* processes are in different namespaces */
	return 0;
}

/* Mask of target namespaces differing from the caller's per /proc/<pid>/ns/. */
static int expected_setns_all_mask(const int *nsfds, pid_t target)
{
	unsigned int mask = 0;
	int i, ret;

	for (i = 0; i < PIDFD_NS_MAX; i++) {
		const struct ns_info *info = &ns_info[i];

		if (!info->flag || nsfds[i] < 0)
			continue;

		ret = in_same_namespace(nsfds[i], target, info->name);
		if (ret < 0)
			return -1;
		if (ret == 0)
			mask |= info->flag;
	}

	return mask;
}

static void *pause_thread(void *arg)
{
	pause();
	return NULL;
}

/* Test that we can't pass garbage to the kernel. */
TEST_F(current_nsset, invalid_flags)
{
	ASSERT_NE(setns(self->pidfd, 0), 0);
	EXPECT_EQ(errno, EINVAL);

	ASSERT_NE(setns(self->pidfd, -1), 0);
	EXPECT_EQ(errno, EINVAL);

	ASSERT_NE(setns(self->pidfd, CLONE_VM), 0);
	EXPECT_EQ(errno, EINVAL);

	ASSERT_NE(setns(self->pidfd, CLONE_NEWUSER | CLONE_VM), 0);
	EXPECT_EQ(errno, EINVAL);
}

/* Test that we can't attach to a task that has already exited. */
TEST_F(current_nsset, pidfd_exited_child)
{
	int i;
	pid_t pid;

	ASSERT_NE(setns(self->child_pidfd_exited, CLONE_NEWUSER | CLONE_NEWNET),
		  0);
	EXPECT_EQ(errno, ESRCH);

	pid = getpid();
	for (i = 0; i < PIDFD_NS_MAX; i++) {
		const struct ns_info *info = &ns_info[i];
		/* Verify that we haven't changed any namespaces. */
		if (self->nsfds[i] >= 0)
			ASSERT_EQ(in_same_namespace(self->nsfds[i], pid, info->name), 1);
	}
}

TEST_F(current_nsset, pidfd_incremental_setns)
{
	int i;
	pid_t pid;

	pid = getpid();
	for (i = 0; i < PIDFD_NS_MAX; i++) {
		const struct ns_info *info = &ns_info[i];
		int nsfd;

		if (self->child_nsfds1[i] < 0)
			continue;

		if (info->flag) {
			ASSERT_EQ(setns(self->child_pidfd1, info->flag), 0) {
				TH_LOG("%m - Failed to setns to %s namespace of %d via pidfd %d",
				       info->name, self->child_pid1,
				       self->child_pidfd1);
			}
		}

		/* Verify that we have changed to the correct namespaces. */
		if (info->flag == CLONE_NEWPID)
			nsfd = self->nsfds[i];
		else
			nsfd = self->child_nsfds1[i];
		ASSERT_EQ(in_same_namespace(nsfd, pid, info->name), 1) {
			TH_LOG("setns failed to place us correctly into %s namespace of %d via pidfd %d",
			       info->name, self->child_pid1,
			       self->child_pidfd1);
		}
		TH_LOG("Managed to correctly setns to %s namespace of %d via pidfd %d",
		       info->name, self->child_pid1, self->child_pidfd1);
	}
}

TEST_F(current_nsset, nsfd_incremental_setns)
{
	int i;
	pid_t pid;

	pid = getpid();
	for (i = 0; i < PIDFD_NS_MAX; i++) {
		const struct ns_info *info = &ns_info[i];
		int nsfd;

		if (self->child_nsfds1[i] < 0)
			continue;

		if (info->flag) {
			ASSERT_EQ(setns(self->child_nsfds1[i], info->flag), 0) {
				TH_LOG("%m - Failed to setns to %s namespace of %d via nsfd %d",
				       info->name, self->child_pid1,
				       self->child_nsfds1[i]);
			}
		}

		/* Verify that we have changed to the correct namespaces. */
		if (info->flag == CLONE_NEWPID)
			nsfd = self->nsfds[i];
		else
			nsfd = self->child_nsfds1[i];
		ASSERT_EQ(in_same_namespace(nsfd, pid, info->name), 1) {
			TH_LOG("setns failed to place us correctly into %s namespace of %d via nsfd %d",
			       info->name, self->child_pid1,
			       self->child_nsfds1[i]);
		}
		TH_LOG("Managed to correctly setns to %s namespace of %d via nsfd %d",
		       info->name, self->child_pid1, self->child_nsfds1[i]);
	}
}

TEST_F(current_nsset, pidfd_derived_nsfd_incremental_setns)
{
	int i;
	pid_t pid;

	pid = getpid();
	for (i = 0; i < PIDFD_NS_MAX; i++) {
		const struct ns_info *info = &ns_info[i];
		int nsfd;

		if (self->child_pidfd_derived_nsfds1[i] < 0)
			continue;

		if (info->flag) {
			ASSERT_EQ(setns(self->child_pidfd_derived_nsfds1[i], info->flag), 0) {
				TH_LOG("%m - Failed to setns to %s namespace of %d via nsfd %d",
				       info->name, self->child_pid1,
				       self->child_pidfd_derived_nsfds1[i]);
			}
		}

		/* Verify that we have changed to the correct namespaces. */
		if (info->flag == CLONE_NEWPID)
			nsfd = self->child_pidfd_derived_nsfds[i];
		else
			nsfd = self->child_pidfd_derived_nsfds1[i];
		ASSERT_EQ(in_same_namespace(nsfd, pid, info->name), 1) {
			TH_LOG("setns failed to place us correctly into %s namespace of %d via nsfd %d",
			       info->name, self->child_pid1,
			       self->child_pidfd_derived_nsfds1[i]);
		}
		TH_LOG("Managed to correctly setns to %s namespace of %d via nsfd %d",
		       info->name, self->child_pid1, self->child_pidfd_derived_nsfds1[i]);
	}
}

TEST_F(current_nsset, pidfd_one_shot_setns)
{
	unsigned flags = 0;
	int i;
	pid_t pid;

	for (i = 0; i < PIDFD_NS_MAX; i++) {
		const struct ns_info *info = &ns_info[i];

		if (self->child_nsfds1[i] < 0)
			continue;

		flags |= info->flag;
		TH_LOG("Adding %s namespace of %d to list of namespaces to attach to",
		       info->name, self->child_pid1);
	}

	ASSERT_EQ(setns(self->child_pidfd1, flags), 0) {
		TH_LOG("%m - Failed to setns to namespaces of %d",
		       self->child_pid1);
	}

	pid = getpid();
	for (i = 0; i < PIDFD_NS_MAX; i++) {
		const struct ns_info *info = &ns_info[i];
		int nsfd;

		if (self->child_nsfds1[i] < 0)
			continue;

		/* Verify that we have changed to the correct namespaces. */
		if (info->flag == CLONE_NEWPID)
			nsfd = self->nsfds[i];
		else
			nsfd = self->child_nsfds1[i];
		ASSERT_EQ(in_same_namespace(nsfd, pid, info->name), 1) {
			TH_LOG("setns failed to place us correctly into %s namespace of %d",
			       info->name, self->child_pid1);
		}
		TH_LOG("Managed to correctly setns to %s namespace of %d",
		       info->name, self->child_pid1);
	}
}

TEST_F(current_nsset, no_foul_play)
{
	unsigned flags = 0;
	int i;

	for (i = 0; i < PIDFD_NS_MAX; i++) {
		const struct ns_info *info = &ns_info[i];

		if (self->child_nsfds1[i] < 0)
			continue;

		flags |= info->flag;
		if (info->flag) /* No use logging pid_for_children. */
			TH_LOG("Adding %s namespace of %d to list of namespaces to attach to",
			       info->name, self->child_pid1);
	}

	ASSERT_EQ(setns(self->child_pidfd1, flags), 0) {
		TH_LOG("%m - Failed to setns to namespaces of %d vid pidfd %d",
		       self->child_pid1, self->child_pidfd1);
	}

	/*
	 * Can't setns to a user namespace outside of our hierarchy since we
	 * don't have caps in there and didn't create it. That means that under
	 * no circumstances should we be able to setns to any of the other
	 * ones since they aren't owned by our user namespace.
	 */
	for (i = 0; i < PIDFD_NS_MAX; i++) {
		const struct ns_info *info = &ns_info[i];

		if (self->child_nsfds2[i] < 0 || !info->flag)
			continue;

		ASSERT_NE(setns(self->child_pidfd2, info->flag), 0) {
			TH_LOG("Managed to setns to %s namespace of %d via pidfd %d",
			       info->name, self->child_pid2,
			       self->child_pidfd2);
		}
		TH_LOG("%m - Correctly failed to setns to %s namespace of %d via pidfd %d",
		       info->name, self->child_pid2,
		       self->child_pidfd2);

		ASSERT_NE(setns(self->child_nsfds2[i], info->flag), 0) {
			TH_LOG("Managed to setns to %s namespace of %d via nsfd %d",
			       info->name, self->child_pid2,
			       self->child_nsfds2[i]);
		}
		TH_LOG("%m - Correctly failed to setns to %s namespace of %d via nsfd %d",
		       info->name, self->child_pid2,
		       self->child_nsfds2[i]);
	}

	/*
	 * Can't setns to a user namespace outside of our hierarchy since we
	 * don't have caps in there and didn't create it. That means that under
	 * no circumstances should we be able to setns to any of the other
	 * ones since they aren't owned by our user namespace.
	 */
	for (i = 0; i < PIDFD_NS_MAX; i++) {
		const struct ns_info *info = &ns_info[i];

		if (self->child_pidfd_derived_nsfds2[i] < 0 || !info->flag)
			continue;

		ASSERT_NE(setns(self->child_pidfd_derived_nsfds2[i], info->flag), 0) {
			TH_LOG("Managed to setns to %s namespace of %d via nsfd %d",
			       info->name, self->child_pid2,
			       self->child_pidfd_derived_nsfds2[i]);
		}
		TH_LOG("%m - Correctly failed to setns to %s namespace of %d via nsfd %d",
		       info->name, self->child_pid2,
		       self->child_pidfd_derived_nsfds2[i]);
	}
}

/* Test that SETNS_ALL joins all differing namespaces and returns their mask. */
TEST_F(current_nsset, setns_all_full_join)
{
	int expected, ret;
	int i;
	pid_t pid;

	expected = expected_setns_all_mask(self->nsfds, self->child_pid1);
	ASSERT_GT(expected, 0);

	ret = setns(self->child_pidfd1, SETNS_ALL);
	ASSERT_EQ(ret, expected) {
		TH_LOG("%m - Failed to SETNS_ALL to namespaces of %d via pidfd %d",
		       self->child_pid1, self->child_pidfd1);
	}

	pid = getpid();
	for (i = 0; i < PIDFD_NS_MAX; i++) {
		const struct ns_info *info = &ns_info[i];
		int nsfd;

		if (self->child_nsfds1[i] < 0)
			continue;

		/* Verify that we have changed to the correct namespaces. */
		if (info->flag == CLONE_NEWPID)
			nsfd = self->nsfds[i];
		else
			nsfd = self->child_nsfds1[i];
		ASSERT_EQ(in_same_namespace(nsfd, pid, info->name), 1) {
			TH_LOG("SETNS_ALL failed to place us correctly into %s namespace of %d",
			       info->name, self->child_pid1);
		}
	}
}

/* Test that SETNS_ALL skips namespaces shared with the target. */
TEST_F(current_nsset, setns_all_same_userns)
{
	int expected, ret;
	int ipc_sockets[2];
	int child_pidfd;
	pid_t child_pid;
	pid_t pid;
	char c;

	if (geteuid())
		SKIP(return, "Test requires root");
	if (self->nsfds[PIDFD_NS_UTS] < 0 || self->nsfds[PIDFD_NS_IPC] < 0 ||
	    self->nsfds[PIDFD_NS_NET] < 0)
		SKIP(return, "Required namespaces are not available");

	ret = socketpair(AF_LOCAL, SOCK_STREAM | SOCK_CLOEXEC, 0, ipc_sockets);
	ASSERT_EQ(ret, 0);

	/* Create a target that shares our user namespace. */
	child_pid = create_child(&child_pidfd, 0);
	EXPECT_GE(child_pid, 0);

	if (child_pid == 0) {
		close(ipc_sockets[0]);

		if (unshare(CLONE_NEWUTS | CLONE_NEWIPC | CLONE_NEWNET) < 0)
			_exit(EXIT_FAILURE);

		if (write_nointr(ipc_sockets[1], "1", 1) < 0)
			_exit(EXIT_FAILURE);

		close(ipc_sockets[1]);

		pause();
		_exit(EXIT_SUCCESS);
	}

	close(ipc_sockets[1]);
	ASSERT_EQ(read_nointr(ipc_sockets[0], &c, 1), 1);
	close(ipc_sockets[0]);

	expected = expected_setns_all_mask(self->nsfds, child_pid);
	ASSERT_EQ(expected, CLONE_NEWUTS | CLONE_NEWIPC | CLONE_NEWNET);

	ret = setns(child_pidfd, SETNS_ALL);
	ASSERT_EQ(ret, expected) {
		TH_LOG("%m - Failed to SETNS_ALL to namespaces of %d via pidfd %d",
		       child_pid, child_pidfd);
	}

	pid = getpid();
	/* The shared user namespace must have been skipped. */
	if (self->nsfds[PIDFD_NS_USER] >= 0)
		ASSERT_EQ(in_same_namespace(self->nsfds[PIDFD_NS_USER], pid, "user"), 1);
	/* Verify that we have changed to the correct namespaces. */
	ASSERT_EQ(in_same_namespace(self->nsfds[PIDFD_NS_UTS], pid, "uts"), 0);
	ASSERT_EQ(in_same_namespace(self->nsfds[PIDFD_NS_IPC], pid, "ipc"), 0);
	ASSERT_EQ(in_same_namespace(self->nsfds[PIDFD_NS_NET], pid, "net"), 0);

	ASSERT_EQ(sys_pidfd_send_signal(child_pidfd, SIGKILL, NULL, 0), 0);
	ASSERT_EQ(sys_waitid(P_PID, child_pid, NULL, WEXITED), 0);
	close(child_pidfd);
}

/* Test that SETNS_ALL on a target sharing everything changes nothing. */
TEST_F(current_nsset, setns_all_self)
{
	int i;
	pid_t pid;

	ASSERT_EQ(setns(self->pidfd, SETNS_ALL), 0);

	pid = getpid();
	for (i = 0; i < PIDFD_NS_MAX; i++) {
		const struct ns_info *info = &ns_info[i];
		/* Verify that we haven't changed any namespaces. */
		if (self->nsfds[i] >= 0)
			ASSERT_EQ(in_same_namespace(self->nsfds[i], pid, info->name), 1);
	}

	/* An identical active time namespace is skipped even with a pending unshare. */
	if (self->nsfds[PIDFD_NS_TIMECLD] >= 0 && geteuid() == 0) {
		int timecld;

		ASSERT_EQ(unshare(CLONE_NEWTIME), 0);
		timecld = preserve_ns(pid, "time_for_children");
		ASSERT_GE(timecld, 0);

		ASSERT_EQ(setns(self->pidfd, SETNS_ALL), 0);

		/* Verify that the pending time namespace has been preserved. */
		ASSERT_EQ(in_same_namespace(timecld, pid, "time_for_children"), 1);
		close(timecld);
	}
}

/* Test that SETNS_ALL can be restricted to a subset of namespaces. */
TEST_F(current_nsset, setns_all_subset)
{
	int expected, ret;
	pid_t pid;

	if (self->nsfds[PIDFD_NS_UTS] < 0 || self->nsfds[PIDFD_NS_NET] < 0)
		SKIP(return, "Required namespaces are not available");

	expected = expected_setns_all_mask(self->nsfds, self->child_pid1);
	ASSERT_GT(expected, 0);
	ASSERT_EQ(expected & (CLONE_NEWUTS | CLONE_NEWNET),
		  CLONE_NEWUTS | CLONE_NEWNET);

	ret = setns(self->child_pidfd1, SETNS_ALL | CLONE_NEWUTS | CLONE_NEWNET);
	ASSERT_EQ(ret, CLONE_NEWUTS | CLONE_NEWNET) {
		TH_LOG("%m - Failed to SETNS_ALL to uts and net namespace of %d via pidfd %d",
		       self->child_pid1, self->child_pidfd1);
	}

	pid = getpid();
	/* Verify that we have changed to the correct namespaces. */
	ASSERT_EQ(in_same_namespace(self->child_nsfds1[PIDFD_NS_UTS], pid, "uts"), 1);
	ASSERT_EQ(in_same_namespace(self->child_nsfds1[PIDFD_NS_NET], pid, "net"), 1);
	/* Verify that no other namespace has been joined. */
	if (self->nsfds[PIDFD_NS_USER] >= 0)
		ASSERT_EQ(in_same_namespace(self->nsfds[PIDFD_NS_USER], pid, "user"), 1);
	if (self->nsfds[PIDFD_NS_MNT] >= 0)
		ASSERT_EQ(in_same_namespace(self->nsfds[PIDFD_NS_MNT], pid, "mnt"), 1);
	if (self->nsfds[PIDFD_NS_IPC] >= 0)
		ASSERT_EQ(in_same_namespace(self->nsfds[PIDFD_NS_IPC], pid, "ipc"), 1);

	/* An identical user namespace is skipped, not rejected. */
	if (self->nsfds[PIDFD_NS_USER] >= 0) {
		ASSERT_EQ(setns(self->pidfd, SETNS_ALL | CLONE_NEWUSER), 0);
		ASSERT_EQ(in_same_namespace(self->nsfds[PIDFD_NS_USER], pid, "user"), 1);
	}
}

/* Test that SETNS_ALL rejects invalid combinations and file descriptors. */
TEST_F(current_nsset, setns_all_invalid)
{
	int fd;

	/* Non-namespace flags are rejected. */
	ASSERT_NE(setns(self->pidfd, SETNS_ALL | CLONE_VM), 0);
	EXPECT_EQ(errno, EINVAL);

	/* SETNS_ALL is only valid with pidfds. */
	if (self->nsfds[PIDFD_NS_NET] >= 0) {
		ASSERT_NE(setns(self->nsfds[PIDFD_NS_NET], SETNS_ALL), 0);
		EXPECT_EQ(errno, EINVAL);
	}

	fd = sys_memfd_create("rostock", 0);
	EXPECT_GT(fd, 0);

	ASSERT_NE(setns(fd, SETNS_ALL), 0);
	EXPECT_EQ(errno, EINVAL);
	close(fd);
}

/* Test that SETNS_ALL fails on a target that has already exited. */
TEST_F(current_nsset, setns_all_exited_child)
{
	int i;
	pid_t pid;

	ASSERT_NE(setns(self->child_pidfd_exited, SETNS_ALL), 0);
	EXPECT_EQ(errno, ESRCH);

	pid = getpid();
	for (i = 0; i < PIDFD_NS_MAX; i++) {
		const struct ns_info *info = &ns_info[i];
		/* Verify that we haven't changed any namespaces. */
		if (self->nsfds[i] >= 0)
			ASSERT_EQ(in_same_namespace(self->nsfds[i], pid, info->name), 1);
	}
}

/* Test that a failing install leaves all namespaces untouched. */
TEST_F(current_nsset, setns_all_atomic)
{
	int expected, ret;
	int ipc_sockets[2];
	int child_pidfd;
	pid_t child_pid;
	pthread_t thread;
	pid_t pid;
	int i;
	char c;

	if (geteuid())
		SKIP(return, "Test requires root");
	if (self->nsfds[PIDFD_NS_UTS] < 0 || self->nsfds[PIDFD_NS_NET] < 0 ||
	    self->nsfds[PIDFD_NS_TIME] < 0)
		SKIP(return, "Required namespaces are not available");

	ret = socketpair(AF_LOCAL, SOCK_STREAM | SOCK_CLOEXEC, 0, ipc_sockets);
	ASSERT_EQ(ret, 0);

	/* Create a target whose time namespace join must fail. */
	child_pid = create_child(&child_pidfd, 0);
	EXPECT_GE(child_pid, 0);

	if (child_pid == 0) {
		close(ipc_sockets[0]);

		if (unshare(CLONE_NEWUTS | CLONE_NEWNET) < 0)
			_exit(EXIT_FAILURE);
		if (!switch_timens())
			_exit(EXIT_FAILURE);

		if (write_nointr(ipc_sockets[1], "1", 1) < 0)
			_exit(EXIT_FAILURE);

		close(ipc_sockets[1]);

		pause();
		_exit(EXIT_SUCCESS);
	}

	close(ipc_sockets[1]);
	ASSERT_EQ(read_nointr(ipc_sockets[0], &c, 1), 1);
	close(ipc_sockets[0]);

	expected = expected_setns_all_mask(self->nsfds, child_pid);
	ASSERT_EQ(expected, CLONE_NEWUTS | CLONE_NEWNET | CLONE_NEWTIME);

	/* A second thread makes joining the time namespace fail with EUSERS. */
	ASSERT_EQ(pthread_create(&thread, NULL, pause_thread, NULL), 0);

	ret = setns(child_pidfd, SETNS_ALL);
	ASSERT_EQ(ret, -1);
	EXPECT_EQ(errno, EUSERS);

	pid = getpid();
	for (i = 0; i < PIDFD_NS_MAX; i++) {
		const struct ns_info *info = &ns_info[i];
		/* Verify that we haven't changed any namespaces. */
		if (self->nsfds[i] >= 0)
			ASSERT_EQ(in_same_namespace(self->nsfds[i], pid, info->name), 1);
	}

	ASSERT_EQ(sys_pidfd_send_signal(child_pidfd, SIGKILL, NULL, 0), 0);
	ASSERT_EQ(sys_waitid(P_PID, child_pid, NULL, WEXITED), 0);
	close(child_pidfd);
}

TEST(setns_einval)
{
	int fd;

	fd = sys_memfd_create("rostock", 0);
	EXPECT_GT(fd, 0);

	ASSERT_NE(setns(fd, 0), 0);
	EXPECT_EQ(errno, EINVAL);
	close(fd);
}

TEST_HARNESS_MAIN
