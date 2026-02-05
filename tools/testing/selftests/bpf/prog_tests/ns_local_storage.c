// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2026 Christian Brauner (Amutable) <brauner@kernel.org> */

#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <sched.h>
#include <signal.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <linux/nsfs.h>
#include <test_progs.h>
#include "ns_ls_lsm.skel.h"
#include "ns_ls_recursion.skel.h"
#include "ns_ls_negative.skel.h"
#include "ns_ls_sleepable.skel.h"
#include "ns_ls_untrusted.skel.h"

#ifndef CLONE_NEWUTS
#define CLONE_NEWUTS 0x04000000
#endif

#ifndef CLONE_NEWIPC
#define CLONE_NEWIPC 0x08000000
#endif

struct ns_storage_val {
	__u64 cookie;
};

/* Userspace CRUD via bpf_map_*_elem() */
static void test_syscall_crud(void)
{
	struct ns_storage_val val = {}, lookup = {};
	__u64 ns_id = 0, bogus, next;
	struct ns_ls_lsm *skel;
	int map_fd, err, status;
	int pipefd[2];
	pid_t child;

	skel = ns_ls_lsm__open_and_load();
	if (!ASSERT_OK_PTR(skel, "open_and_load"))
		return;
	map_fd = bpf_map__fd(skel->maps.ns_map);

	if (!ASSERT_OK(pipe(pipefd), "pipe"))
		goto destroy;

	child = fork();
	if (!ASSERT_GE(child, 0, "fork"))
		goto destroy;

	if (child == 0) {
		int nsfd;

		close(pipefd[0]);
		if (unshare(CLONE_NEWUTS))
			_exit(1);
		nsfd = open("/proc/self/ns/uts", O_RDONLY);
		if (nsfd < 0)
			_exit(2);
		if (ioctl(nsfd, NS_GET_ID, &ns_id))
			_exit(3);
		close(nsfd);
		write(pipefd[1], &ns_id, sizeof(ns_id));
		close(pipefd[1]);
		pause();
		_exit(0);
	}

	close(pipefd[1]);
	ASSERT_EQ(read(pipefd[0], &ns_id, sizeof(ns_id)),
		  (ssize_t)sizeof(ns_id), "read_ns_id");
	close(pipefd[0]);
	ASSERT_GT(ns_id, 0ULL, "ns_id_nonzero");

	/* CREATE */
	val.cookie = 0x0A110C01;
	err = bpf_map_update_elem(map_fd, &ns_id, &val, BPF_ANY);
	ASSERT_OK(err, "update_create");

	/* LOOKUP */
	err = bpf_map_lookup_elem(map_fd, &ns_id, &lookup);
	ASSERT_OK(err, "lookup");
	ASSERT_EQ(lookup.cookie, 0x0A110C01, "lookup_value");

	/* UPDATE existing */
	val.cookie = 0x0A110C02;
	err = bpf_map_update_elem(map_fd, &ns_id, &val, BPF_EXIST);
	ASSERT_OK(err, "update_exist");
	err = bpf_map_lookup_elem(map_fd, &ns_id, &lookup);
	ASSERT_OK(err, "lookup_after_update");
	ASSERT_EQ(lookup.cookie, 0x0A110C02, "updated_value");

	/* DELETE */
	err = bpf_map_delete_elem(map_fd, &ns_id);
	ASSERT_OK(err, "delete");

	/* LOOKUP after DELETE -> ENOENT */
	err = bpf_map_lookup_elem(map_fd, &ns_id, &lookup);
	ASSERT_ERR(err, "lookup_after_delete");

	/* Double DELETE -> ENOENT */
	err = bpf_map_delete_elem(map_fd, &ns_id);
	ASSERT_ERR(err, "double_delete");

	/* Bogus ns_id -> ENOENT */
	bogus = 0xFFFFFFFFFFFFFFFFULL;
	err = bpf_map_lookup_elem(map_fd, &bogus, &lookup);
	ASSERT_ERR(err, "lookup_bogus_id");

	/* GET_NEXT_KEY -> ENOTSUPP */
	err = bpf_map_get_next_key(map_fd, &ns_id, &next);
	ASSERT_ERR(err, "get_next_key");

	kill(child, SIGTERM);
	waitpid(child, &status, 0);
destroy:
	ns_ls_lsm__destroy(skel);
}

/* Map creation parameter validation */
static void test_map_create_checks(void)
{
	LIBBPF_OPTS(bpf_map_create_opts, opts);
	int fd;

	/* Missing BPF_F_NO_PREALLOC -> EINVAL */
	opts.map_flags = 0;
	fd = bpf_map_create(BPF_MAP_TYPE_NS_STORAGE, "bad1",
			    sizeof(__u64), sizeof(__u64), 0, &opts);
	if (!ASSERT_LT(fd, 0, "no_prealloc"))
		close(fd);

	/* Non-zero max_entries -> EINVAL */
	opts.map_flags = BPF_F_NO_PREALLOC;
	fd = bpf_map_create(BPF_MAP_TYPE_NS_STORAGE, "bad2",
			    sizeof(__u64), sizeof(__u64), 1, &opts);
	if (!ASSERT_LT(fd, 0, "nonzero_max_entries"))
		close(fd);

	/* Zero value_size -> EINVAL */
	fd = bpf_map_create(BPF_MAP_TYPE_NS_STORAGE, "bad3",
			    sizeof(__u64), 0, 0, &opts);
	if (!ASSERT_LT(fd, 0, "zero_value_size"))
		close(fd);

	/* Invalid flags -> EINVAL */
	opts.map_flags = BPF_F_NO_PREALLOC | BPF_F_RDONLY_PROG;
	fd = bpf_map_create(BPF_MAP_TYPE_NS_STORAGE, "bad4",
			    sizeof(__u64), sizeof(__u64), 0, &opts);
	if (!ASSERT_LT(fd, 0, "invalid_flags"))
		close(fd);
}

/* BPF-side kfunc GET and DELETE */
static void test_lsm_kfunc(void)
{
	struct ns_ls_lsm *skel;
	int err, status;
	pid_t child;

	skel = ns_ls_lsm__open();
	if (!ASSERT_OK_PTR(skel, "open"))
		return;

	bpf_program__set_autoload(skel->progs.ns_kfunc_test, true);

	err = ns_ls_lsm__load(skel);
	if (!ASSERT_OK(err, "load"))
		goto out;

	err = ns_ls_lsm__attach(skel);
	if (!ASSERT_OK(err, "attach"))
		goto out;

	/*
	 * Must trigger from a dynamically created namespace.
	 * Init namespaces don't have BPF security blobs
	 * (statically initialized via NS_COMMON_INIT).
	 */
	child = fork();
	if (!ASSERT_GE(child, 0, "fork"))
		goto out;

	if (child == 0) {
		int tmpfd;

		if (unshare(CLONE_NEWUTS))
			_exit(1);
		skel->bss->target_pid = getpid();
		tmpfd = open("/dev/null", O_RDONLY);
		if (tmpfd >= 0)
			close(tmpfd);
		skel->bss->target_pid = 0;
		_exit(0);
	}

	waitpid(child, &status, 0);
	if (!ASSERT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == 0,
			 "child_ok"))
		goto out;

	ASSERT_EQ(skel->bss->kfunc_get_success, 1, "get_success");
	ASSERT_EQ(skel->bss->kfunc_read_value, 0x0A110C01, "read_value");
	ASSERT_EQ(skel->bss->kfunc_delete_success, 1, "delete_success");

out:
	ns_ls_lsm__destroy(skel);
}

/* Multiple maps on the same namespace */
static void test_multi_map(void)
{
	struct ns_storage_val lookup_a = {};
	struct ns_ls_lsm *skel;
	int map_a_fd, map_b_fd, err, status;
	__u64 ns_id = 0;
	__u64 lookup_b = 0;
	int pipefd[2];
	pid_t child;

	skel = ns_ls_lsm__open();
	if (!ASSERT_OK_PTR(skel, "open"))
		return;

	bpf_program__set_autoload(skel->progs.ns_multi_map_test, true);

	err = ns_ls_lsm__load(skel);
	if (!ASSERT_OK(err, "load"))
		goto out;

	err = ns_ls_lsm__attach(skel);
	if (!ASSERT_OK(err, "attach"))
		goto out;

	if (!ASSERT_OK(pipe(pipefd), "pipe"))
		goto out;

	child = fork();
	if (!ASSERT_GE(child, 0, "fork")) {
		close(pipefd[0]);
		close(pipefd[1]);
		goto out;
	}

	if (child == 0) {
		int nsfd, tmpfd;

		close(pipefd[0]);
		if (unshare(CLONE_NEWUTS))
			_exit(1);

		nsfd = open("/proc/self/ns/uts", O_RDONLY);
		if (nsfd < 0)
			_exit(2);
		if (ioctl(nsfd, NS_GET_ID, &ns_id))
			_exit(3);
		close(nsfd);

		/* Trigger lsm/file_open to populate both maps */
		skel->bss->target_pid = getpid();
		tmpfd = open("/dev/null", O_RDONLY);
		if (tmpfd >= 0)
			close(tmpfd);
		skel->bss->target_pid = 0;

		write(pipefd[1], &ns_id, sizeof(ns_id));
		close(pipefd[1]);
		/* Keep child alive so namespace stays in tree */
		pause();
		_exit(0);
	}

	close(pipefd[1]);
	ASSERT_EQ(read(pipefd[0], &ns_id, sizeof(ns_id)),
		  (ssize_t)sizeof(ns_id), "read_ns_id");
	close(pipefd[0]);
	ASSERT_GT(ns_id, 0ULL, "ns_id_nonzero");

	ASSERT_EQ(skel->bss->multi_map_a_ok, 1, "map_a_created");
	ASSERT_EQ(skel->bss->multi_map_b_ok, 1, "map_b_created");

	/* Verify from userspace while child's namespace is alive */
	map_a_fd = bpf_map__fd(skel->maps.ns_map);
	map_b_fd = bpf_map__fd(skel->maps.ns_map_b);

	err = bpf_map_lookup_elem(map_a_fd, &ns_id, &lookup_a);
	ASSERT_OK(err, "lookup_map_a");
	ASSERT_EQ(lookup_a.cookie, 0x0A110C02, "map_a_value");

	err = bpf_map_lookup_elem(map_b_fd, &ns_id, &lookup_b);
	ASSERT_OK(err, "lookup_map_b");
	ASSERT_EQ(lookup_b, 0x42, "map_b_value");

	kill(child, SIGTERM);
	waitpid(child, &status, 0);

out:
	ns_ls_lsm__destroy(skel);
}

/* BPF denies namespace creation */
static void test_deny_alloc(void)
{
	struct ns_ls_lsm *skel;
	int err, status;
	pid_t child;

	skel = ns_ls_lsm__open();
	if (!ASSERT_OK_PTR(skel, "open"))
		return;

	bpf_program__set_autoload(skel->progs.ns_alloc_deny, true);

	err = ns_ls_lsm__load(skel);
	if (!ASSERT_OK(err, "load"))
		goto out;

	err = ns_ls_lsm__attach(skel);
	if (!ASSERT_OK(err, "attach"))
		goto out;

	skel->bss->deny_alloc_active = 1;

	/* Fork child to avoid polluting parent's namespace state */
	child = fork();
	if (!ASSERT_GE(child, 0, "fork"))
		goto out;
	if (child == 0) {
		if (unshare(CLONE_NEWUTS) == 0)
			_exit(1);  /* should have failed */
		_exit(0);      /* good: unshare failed as expected */
	}
	waitpid(child, &status, 0);
	ASSERT_TRUE(WIFEXITED(status), "child_exited");
	ASSERT_EQ(WEXITSTATUS(status), 0, "unshare_was_denied");

	skel->bss->deny_alloc_active = 0;

	/* Verify unshare works after disabling denial */
	child = fork();
	if (!ASSERT_GE(child, 0, "fork2"))
		goto out;
	if (child == 0) {
		if (unshare(CLONE_NEWUTS))
			_exit(1);
		_exit(0);
	}
	waitpid(child, &status, 0);
	ASSERT_TRUE(WIFEXITED(status), "child2_exited");
	ASSERT_EQ(WEXITSTATUS(status), 0, "unshare_after_disable");

out:
	ns_ls_lsm__destroy(skel);
}

/*
 * Storage freed on namespace teardown.
 */
static void test_cleanup_on_ns_destroy(void)
{
	struct ns_storage_val lookup = {};
	struct ns_ls_lsm *skel;
	int map_fd, err, status;
	pid_t child = -1;
	__u64 ns_id = 0;
	int pipefd[2];

	skel = ns_ls_lsm__open_and_load();
	if (!ASSERT_OK_PTR(skel, "open_and_load"))
		return;

	map_fd = bpf_map__fd(skel->maps.ns_map);
	if (!ASSERT_OK(pipe(pipefd), "pipe"))
		goto out;

	child = fork();
	if (!ASSERT_GE(child, 0, "fork")) {
		close(pipefd[0]);
		close(pipefd[1]);
		goto out;
	}

	if (child == 0) {
		struct ns_storage_val v = { .cookie = 0x0A110C04 };
		int nsfd;

		close(pipefd[0]);
		if (unshare(CLONE_NEWUTS))
			_exit(1);

		nsfd = open("/proc/self/ns/uts", O_RDONLY);
		if (nsfd < 0)
			_exit(2);
		if (ioctl(nsfd, NS_GET_ID, &ns_id))
			_exit(3);
		close(nsfd);

		/* Populate storage via userspace */
		bpf_map_update_elem(map_fd, &ns_id, &v, BPF_ANY);

		write(pipefd[1], &ns_id, sizeof(ns_id));
		close(pipefd[1]);
		pause();
		_exit(0);
	}

	close(pipefd[1]);
	ASSERT_EQ(read(pipefd[0], &ns_id, sizeof(ns_id)),
		  (ssize_t)sizeof(ns_id), "read_ns_id");
	close(pipefd[0]);
	ASSERT_GT(ns_id, 0ULL, "ns_id_valid");

	/* Verify storage exists while child is alive */
	err = bpf_map_lookup_elem(map_fd, &ns_id, &lookup);
	ASSERT_OK(err, "lookup_while_alive");
	ASSERT_EQ(lookup.cookie, 0x0A110C04, "cookie_alive");

	/* Kill child -> namespace destroyed */
	kill(child, SIGTERM);
	waitpid(child, &status, 0);
	child = -1;

	/* Wait for async namespace free + RCU grace periods */
	kern_sync_rcu();
	kern_sync_rcu();

	/* Namespace is gone -> storage should be cleaned up */
	err = bpf_map_lookup_elem(map_fd, &ns_id, &lookup);
	ASSERT_ERR(err, "lookup_after_destroy");

out:
	if (child > 0) {
		kill(child, SIGTERM);
		waitpid(child, &status, 0);
	}
	ns_ls_lsm__destroy(skel);
}

/* Per-CPU busy counter with sequential calls */
static void test_recursion(void)
{
	struct ns_ls_recursion *skel;
	int err, status;
	pid_t child;

	skel = ns_ls_recursion__open_and_load();
	if (!ASSERT_OK_PTR(skel, "open_and_load"))
		return;

	err = ns_ls_recursion__attach(skel);
	if (!ASSERT_OK(err, "attach"))
		goto out;

	child = fork();
	if (!ASSERT_GE(child, 0, "fork"))
		goto out;

	if (child == 0) {
		int tmpfd;

		if (unshare(CLONE_NEWUTS))
			_exit(1);
		skel->bss->target_pid = getpid();
		tmpfd = open("/dev/null", O_RDONLY);
		if (tmpfd >= 0)
			close(tmpfd);
		skel->bss->target_pid = 0;
		_exit(0);
	}

	waitpid(child, &status, 0);
	if (!ASSERT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == 0,
			 "child_ok"))
		goto out;

	ASSERT_EQ(skel->bss->map_a_ok, 1, "map_a_created");
	ASSERT_EQ(skel->bss->delete_ok, 1, "delete_succeeded");
	ASSERT_EQ(skel->bss->recreate_ok, 1, "recreate_after_delete");
	ASSERT_EQ(skel->bss->map_b_ok, 1, "map_b_created");

out:
	ns_ls_recursion__destroy(skel);
}

/* Verifier rejects wrong program type */
static void test_negative(void)
{
	struct ns_ls_negative *skel;

	skel = ns_ls_negative__open_and_load();
	if (!ASSERT_ERR_PTR(skel, "open_and_load")) {
		ns_ls_negative__destroy(skel);
		return;
	}
}

/* Sleepable LSM program with NS_STORAGE */
static void test_sleepable(void)
{
	struct ns_ls_sleepable *skel;
	int err, status;
	pid_t child;

	skel = ns_ls_sleepable__open();
	if (!ASSERT_OK_PTR(skel, "open"))
		return;

	bpf_program__set_autoload(skel->progs.sleepable_ns_storage, true);

	err = ns_ls_sleepable__load(skel);
	if (!ASSERT_OK(err, "load"))
		goto out;

	err = ns_ls_sleepable__attach(skel);
	if (!ASSERT_OK(err, "attach"))
		goto out;

	child = fork();
	if (!ASSERT_GE(child, 0, "fork"))
		goto out;

	if (child == 0) {
		int tmpfd;

		if (unshare(CLONE_NEWUTS))
			_exit(1);
		skel->bss->target_pid = getpid();
		tmpfd = open("/dev/null", O_RDONLY);
		if (tmpfd >= 0)
			close(tmpfd);
		skel->bss->target_pid = 0;
		_exit(0);
	}

	waitpid(child, &status, 0);
	if (!ASSERT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == 0,
			 "child_ok"))
		goto out;

	ASSERT_EQ(skel->bss->get_success, 1, "sleepable_get");
	ASSERT_EQ(skel->bss->read_value, 0x0A110C03, "sleepable_value");

out:
	ns_ls_sleepable__destroy(skel);
}

/*
 * Verifier rejects untrusted hook args passed to KF_RCU kfuncs.
 */
static void test_untrusted(void)
{
	struct ns_ls_untrusted *skel;
	int err;

	/* namespace_free hook arg -> KF_RCU kfunc: must fail */
	skel = ns_ls_untrusted__open();
	if (!ASSERT_OK_PTR(skel, "open_free"))
		return;
	bpf_program__set_autoload(skel->progs.ns_free_untrusted_storage, true);
	err = ns_ls_untrusted__load(skel);
	ASSERT_ERR(err, "load_free_untrusted");
	ns_ls_untrusted__destroy(skel);
}

/*
 * Storage creation directly from the namespace_alloc hook.
 */
static void test_alloc_storage(void)
{
	struct ns_ls_lsm *skel;
	int err, status;
	pid_t child;

	skel = ns_ls_lsm__open();
	if (!ASSERT_OK_PTR(skel, "open"))
		return;

	bpf_program__set_autoload(skel->progs.ns_alloc_storage, true);

	err = ns_ls_lsm__load(skel);
	if (!ASSERT_OK(err, "load"))
		goto out;

	err = ns_ls_lsm__attach(skel);
	if (!ASSERT_OK(err, "attach"))
		goto out;

	skel->bss->alloc_storage_active = 1;

	child = fork();
	if (!ASSERT_GE(child, 0, "fork"))
		goto out;

	if (child == 0) {
		if (unshare(CLONE_NEWUTS))
			_exit(1);
		_exit(0);
	}

	waitpid(child, &status, 0);
	if (!ASSERT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == 0,
			 "child_ok"))
		goto out;

	ASSERT_EQ(skel->bss->alloc_storage_ok, 1, "alloc_storage_ok");
	ASSERT_EQ(skel->bss->alloc_storage_value, 0x0A110C06,
		  "alloc_storage_value");

out:
	ns_ls_lsm__destroy(skel);
}

/* IPC namespace type via bpf_get_current_ns(CLONE_NEWIPC) */
static void test_ipc_namespace(void)
{
	struct ns_ls_lsm *skel;
	int err, status;
	pid_t child;

	skel = ns_ls_lsm__open();
	if (!ASSERT_OK_PTR(skel, "open"))
		return;

	bpf_program__set_autoload(skel->progs.ns_ipc_test, true);

	err = ns_ls_lsm__load(skel);
	if (!ASSERT_OK(err, "load"))
		goto out;

	err = ns_ls_lsm__attach(skel);
	if (!ASSERT_OK(err, "attach"))
		goto out;

	child = fork();
	if (!ASSERT_GE(child, 0, "fork"))
		goto out;

	if (child == 0) {
		int tmpfd;

		if (unshare(CLONE_NEWIPC))
			_exit(1);
		skel->bss->target_pid = getpid();
		tmpfd = open("/dev/null", O_RDONLY);
		if (tmpfd >= 0)
			close(tmpfd);
		skel->bss->target_pid = 0;
		_exit(0);
	}

	waitpid(child, &status, 0);
	if (!ASSERT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == 0,
			 "child_ok"))
		goto out;

	ASSERT_EQ(skel->bss->ipc_get_success, 1, "ipc_get_success");
	ASSERT_EQ(skel->bss->ipc_read_value, 0x0A110C05, "ipc_read_value");

out:
	ns_ls_lsm__destroy(skel);
}

void test_ns_local_storage(void)
{
	if (test__start_subtest("syscall_crud"))
		test_syscall_crud();
	if (test__start_subtest("map_create_checks"))
		test_map_create_checks();
	if (test__start_subtest("lsm_kfunc"))
		test_lsm_kfunc();
	if (test__start_subtest("multi_map"))
		test_multi_map();
	if (test__start_subtest("deny_alloc"))
		test_deny_alloc();
	if (test__start_subtest("alloc_storage"))
		test_alloc_storage();
	if (test__start_subtest("cleanup_on_ns_destroy"))
		test_cleanup_on_ns_destroy();
	if (test__start_subtest("recursion"))
		test_recursion();
	if (test__start_subtest("negative"))
		test_negative();
	if (test__start_subtest("untrusted"))
		test_untrusted();
	if (test__start_subtest("sleepable"))
		test_sleepable();
	if (test__start_subtest("ipc_namespace"))
		test_ipc_namespace();
}
