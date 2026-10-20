// SPDX-License-Identifier: GPL-2.0
/*
 * A refwalk that finds a name whose mounts are detached by an unlink
 * before it looked at them must not step onto what the mounts covered,
 * with or without LOOKUP_REVAL. And it must not keep walking for as long
 * as names keep being removed under it.
 *
 * A raw fuse server provides the timing. It answers the revalidation of
 * a name only after a second thread has unlinked that name through the
 * fuse mount itself, while the walker walks an open_tree() copy of it
 * with a tmpfs file mounted over the name.
 *
 * Requires root to mount fuse.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <poll.h>
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>
#include <linux/fuse.h>

#include "../../kselftest_harness.h"

#ifndef OPEN_TREE_CLONE
#define OPEN_TREE_CLONE		1
#endif
#ifndef OPEN_TREE_CLOEXEC
#define OPEN_TREE_CLOEXEC	O_CLOEXEC
#endif
#ifndef OPEN_TREE_NAMESPACE
#define OPEN_TREE_NAMESPACE	(1 << 1)
#endif
#ifndef MOVE_MOUNT_F_EMPTY_PATH
#define MOVE_MOUNT_F_EMPTY_PATH	0x00000004
#endif

#define NR_SERVERS	8
#define WALK_SECS	5
#define NOBODY		65534

enum {
	ROOT_ID = FUSE_ROOT_ID,
	F1_ID,		/* /f1 */
	LNK_ID,		/* /lnk -> f1 */
	D_ID,		/* /d */
	F_ID,		/* /d/f */
};

/* what a walk must not read: the file the mount covered */
#define UNDER	"UNDER"
#define MARK	"MARK"

static int ffd = -1;
static char fmnt[128], markpath[128];

/* in revalidation: f1 is valid for 3600s, 0 makes every refwalk revalidate it */
static atomic_uint f1_valid;
static atomic_int f1_present;
static atomic_int unlink_f1;		/* unlink F/f1 in the walker's next lookup of f1 */
static atomic_int estale_readlink;	/* fail this pid's next readlink with ESTALE */
static atomic_int walker;

static atomic_int games;		/* make d/f findable and unlink it under the walker */
static atomic_int rename_d;		/* rename d to e in the walker's next revalidation of d */
static atomic_int d_is_e;		/* d has been renamed to e */
static atomic_int cover_tfd = -1;	/* cover d/f in this copy of F as well */
static atomic_int f_findable;
static atomic_long nr_unlinks;
static atomic_int d_present = 1;	/* the server deleted d when 0 */

/* ---- a helper thread runs the syscalls a server thread waits for ---- */

enum job_kind { JOB_NONE, JOB_STAT, JOB_UNLINK, JOB_COVER, JOB_RENAME };

static pthread_mutex_t job_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t job_cond = PTHREAD_COND_INITIALIZER;
static enum job_kind job;
static char job_path[160];
static const char *job_name;
static int job_seq, done_seq, job_ret;

/* mount a copy of @src on @name in the copy @tfd of F */
static int cover_from(int tfd, const char *src, const char *name)
{
	int mfd, ret = 0;

	mfd = syscall(SYS_open_tree, AT_FDCWD, src,
		      OPEN_TREE_CLONE | OPEN_TREE_CLOEXEC);
	if (mfd < 0)
		return -errno;
	if (syscall(SYS_move_mount, mfd, "", tfd, name, MOVE_MOUNT_F_EMPTY_PATH))
		ret = -errno;
	close(mfd);
	return ret;
}

static int cover(int tfd, const char *name)
{
	return cover_from(tfd, markpath, name);
}

/* tell the kernel that @name in @parent, node @child, is gone */
static int notify_delete(uint64_t parent, uint64_t child, const char *name)
{
	struct fuse_notify_delete_out d = {
		.parent = parent,
		.child = child,
		.namelen = strlen(name),
	};
	struct fuse_out_header oh = {
		.len = sizeof(oh) + sizeof(d) + d.namelen + 1,
		.error = FUSE_NOTIFY_DELETE,
	};
	struct iovec iov[3] = {
		{ &oh, sizeof(oh) }, { &d, sizeof(d) }, { (void *)name, d.namelen + 1 }
	};

	return writev(ffd, iov, 3) < 0 ? -errno : 0;
}

static void *helper(void *arg)
{
	pthread_mutex_lock(&job_lock);
	for (;;) {
		struct stat st;
		enum job_kind k;
		int ret, seq;

		while (job == JOB_NONE)
			pthread_cond_wait(&job_cond, &job_lock);
		k = job;
		seq = job_seq;
		job = JOB_NONE;
		pthread_mutex_unlock(&job_lock);

		if (k == JOB_STAT) {
			ret = stat(job_path, &st) ? -errno : 0;
		} else if (k == JOB_UNLINK) {
			ret = unlink(job_path) ? -errno : 0;
		} else if (k == JOB_RENAME) {
			char to[160];

			snprintf(to, sizeof(to), "%s/e", fmnt);
			ret = rename(job_path, to) ? -errno : 0;
		} else {
			ret = cover(atomic_load(&cover_tfd), job_name);
		}

		pthread_mutex_lock(&job_lock);
		job_ret = ret;
		done_seq = seq;
		pthread_cond_broadcast(&job_cond);
	}
	return NULL;
}

/* run @k in the helper and wait for it, for 2s at most */
static int run_job(enum job_kind k, const char *name)
{
	static pthread_mutex_t one_at_a_time = PTHREAD_MUTEX_INITIALIZER;
	struct timespec dl;
	int seq, ret;

	pthread_mutex_lock(&one_at_a_time);
	clock_gettime(CLOCK_REALTIME, &dl);
	dl.tv_sec += 2;
	pthread_mutex_lock(&job_lock);
	seq = ++job_seq;
	job = k;
	job_name = name;
	snprintf(job_path, sizeof(job_path), "%s/%s", fmnt, name);
	pthread_cond_broadcast(&job_cond);
	while (done_seq != seq) {
		if (pthread_cond_timedwait(&job_cond, &job_lock, &dl) == ETIMEDOUT) {
			job_ret = -ETIMEDOUT;
			break;
		}
	}
	ret = done_seq == seq ? job_ret : -ETIMEDOUT;
	pthread_mutex_unlock(&job_lock);
	pthread_mutex_unlock(&one_at_a_time);
	return ret;
}

/* ---- the fuse server ---- */

static void reply(uint64_t unique, int error, const void *data, size_t len)
{
	struct fuse_out_header oh = {
		.len = sizeof(oh) + (error ? 0 : len),
		.error = error,
		.unique = unique,
	};
	struct iovec iov[2] = { { &oh, sizeof(oh) }, { (void *)data, len } };

	/* errors here are teardown races, the device is gone */
	if (writev(ffd, iov, (error || !len) ? 1 : 2) < 0)
		return;
}

static void fill_attr(struct fuse_attr *a, uint64_t id)
{
	memset(a, 0, sizeof(*a));
	a->ino = id;
	a->nlink = 1;
	a->blksize = 4096;
	if (id == ROOT_ID || id == D_ID) {
		a->mode = S_IFDIR | 0755;
		a->nlink = 2;
	} else if (id == LNK_ID) {
		a->mode = S_IFLNK | 0777;
		a->size = 2;
	} else {
		a->mode = S_IFREG | 0644;
		a->size = sizeof(UNDER) - 1;
	}
}

static void reply_entry(uint64_t unique, uint64_t id, uint64_t valid)
{
	struct fuse_entry_out e = {
		.nodeid = id,
		.generation = 1,
		.entry_valid = valid,
		.attr_valid = 3600,
	};

	fill_attr(&e.attr, id);
	reply(unique, 0, &e, sizeof(e));
}

static void lookup(struct fuse_in_header *ih, const char *name)
{
	int w = atomic_load(&walker);
	bool from_walker = w && (int)ih->pid == w;

	if (ih->nodeid == ROOT_ID && !strcmp(name, "f1")) {
		/*
		 * The answer was formed before the unlink went through. A
		 * server is free to send it afterwards.
		 */
		if (from_walker && atomic_exchange(&unlink_f1, 0)) {
			run_job(JOB_UNLINK, "f1");
		} else if (!atomic_load(&f1_present)) {
			reply(ih->unique, -ENOENT, NULL, 0);
			return;
		}
		reply_entry(ih->unique, F1_ID, atomic_load(&f1_valid));
	} else if (ih->nodeid == ROOT_ID && !strcmp(name, "lnk")) {
		reply_entry(ih->unique, LNK_ID, 3600);
	} else if (ih->nodeid == ROOT_ID && (!strcmp(name, "d") || !strcmp(name, "e"))) {
		bool is_e = name[0] == 'e';

		if (!is_e && !atomic_load(&d_present)) {
			reply(ih->unique, -ENOENT, NULL, 0);
			return;
		}
		/*
		 * The walker revalidates d: rename it to e first. The answer
		 * is then about a name the directory no longer has.
		 */
		if (!is_e && from_walker && atomic_exchange(&rename_d, 0))
			run_job(JOB_RENAME, "d");
		if (is_e != !!atomic_load(&d_is_e)) {
			reply(ih->unique, -ENOENT, NULL, 0);
			return;
		}
		/* the walker revalidates d: have d/f looked up (and covered) again */
		if (!is_e && from_walker && atomic_load(&games)) {
			int ret = atomic_load(&cover_tfd) >= 0 ?
				  run_job(JOB_COVER, "d/f") : run_job(JOB_STAT, "d/f");

			if (!ret)
				atomic_store(&f_findable, 1);
		}
		reply_entry(ih->unique, D_ID, 0);
	} else if (ih->nodeid == D_ID && !strcmp(name, "f")) {
		/* the walker revalidates the d/f it found: unlink it first */
		if (from_walker && atomic_load(&games) &&
		    atomic_exchange(&f_findable, 0) &&
		    !run_job(JOB_UNLINK, "d/f"))
			atomic_fetch_add(&nr_unlinks, 1);
		reply_entry(ih->unique, F_ID, 0);
	} else {
		reply(ih->unique, -ENOENT, NULL, 0);
	}
}

static void *server(void *arg)
{
	size_t size = FUSE_MIN_READ_BUFFER + 65536;
	char *buf = malloc(size);
	struct fuse_in_header *ih = (void *)buf;
	void *in = buf + sizeof(*ih);

	if (!buf)
		return NULL;
	for (;;) {
		ssize_t n = read(ffd, buf, size);

		if (n < 0 && (errno == EINTR || errno == EAGAIN))
			continue;
		if (n < (ssize_t)sizeof(*ih))
			return NULL;	/* the mount is gone */

		switch (ih->opcode) {
		case FUSE_INIT: {
			struct fuse_init_out o = {
				.major = FUSE_KERNEL_VERSION,
				.minor = FUSE_KERNEL_MINOR_VERSION,
				.max_readahead = 65536,
				.max_write = 65536,
				.time_gran = 1,
			};

			reply(ih->unique, 0, &o, sizeof(o));
			break;
		}
		case FUSE_LOOKUP:
			lookup(ih, in);
			break;
		case FUSE_GETATTR: {
			struct fuse_attr_out o = { .attr_valid = 3600 };

			fill_attr(&o.attr, ih->nodeid);
			reply(ih->unique, 0, &o, sizeof(o));
			break;
		}
		case FUSE_READLINK: {
			int pid = atomic_load(&estale_readlink);

			/* one failure is enough to get the open to LOOKUP_REVAL */
			if (pid && (int)ih->pid == pid &&
			    atomic_compare_exchange_strong(&estale_readlink, &pid, 0))
				reply(ih->unique, -ESTALE, NULL, 0);
			else
				reply(ih->unique, 0, "f1", 2);
			break;
		}
		case FUSE_OPEN:
		case FUSE_OPENDIR: {
			struct fuse_open_out o = {
				.fh = ih->nodeid,
				.open_flags = FOPEN_DIRECT_IO,
			};

			reply(ih->unique, 0, &o, sizeof(o));
			break;
		}
		case FUSE_READ: {
			struct fuse_read_in *ri = in;
			size_t len = sizeof(UNDER) - 1;

			if (ri->offset >= len)
				reply(ih->unique, 0, NULL, 0);
			else
				reply(ih->unique, 0, UNDER + ri->offset, len - ri->offset);
			break;
		}
		case FUSE_UNLINK:
			if (ih->nodeid == ROOT_ID && !strcmp(in, "f1"))
				atomic_store(&f1_present, 0);
			reply(ih->unique, 0, NULL, 0);
			break;
		case FUSE_RENAME: {
			struct fuse_rename_in *ri = in;
			const char *from = (const char *)(ri + 1);
			const char *to = from + strlen(from) + 1;

			/* only d <-> e in the root */
			if (ih->nodeid != ROOT_ID || ri->newdir != ROOT_ID ||
			    strcmp(from, atomic_load(&d_is_e) ? "e" : "d") ||
			    strcmp(to, atomic_load(&d_is_e) ? "d" : "e")) {
				reply(ih->unique, -EINVAL, NULL, 0);
				break;
			}
			atomic_store(&d_is_e, !atomic_load(&d_is_e));
			reply(ih->unique, 0, NULL, 0);
			break;
		}
		case FUSE_FLUSH:
		case FUSE_RELEASE:
		case FUSE_RELEASEDIR:
		case FUSE_ACCESS:
			reply(ih->unique, 0, NULL, 0);
			break;
		case FUSE_FORGET:
		case FUSE_BATCH_FORGET:
		case FUSE_INTERRUPT:
			break;
		case FUSE_DESTROY:
			reply(ih->unique, 0, NULL, 0);
			return NULL;
		default:
			reply(ih->unique, -ENOSYS, NULL, 0);
			break;
		}
	}
}

/* ---- the walker: a child that opens @path below @dfd once ---- */

struct walk {
	pid_t pid;
	int rfd;
	int err;
	char buf[16];
};

static int walk_start(struct walk *w, int dfd, const char *path, bool estale)
{
	int res[2], go[2];
	char c = 0;

	if (pipe2(res, O_CLOEXEC) || pipe2(go, O_CLOEXEC))
		return -errno;
	w->pid = fork();
	if (w->pid < 0)
		return -errno;
	if (!w->pid) {
		struct { int err; char buf[16]; } r = {};
		int fd;

		close(res[0]);
		close(go[1]);
		if (read(go[0], &c, 1) != 1)
			_exit(1);
		fd = openat(dfd, path, O_RDONLY | O_CLOEXEC);
		if (fd < 0)
			r.err = errno;
		else if (read(fd, r.buf, sizeof(r.buf) - 1) < 0)
			r.err = errno;
		if (write(res[1], &r, sizeof(r)) != sizeof(r))
			_exit(1);
		_exit(0);
	}
	close(res[1]);
	close(go[0]);
	w->rfd = res[0];
	atomic_store(&walker, w->pid);
	if (estale)
		atomic_store(&estale_readlink, w->pid);
	if (write(go[1], &c, 1) != 1)
		return -errno;
	close(go[1]);
	return 0;
}

/* 0 once the walker returned from open(), -ETIMEDOUT if it is still in there */
static int walk_wait(struct walk *w, int secs)
{
	struct pollfd pfd = { .fd = w->rfd, .events = POLLIN };
	struct { int err; char buf[16]; } r;
	int ret = -ETIMEDOUT;

	if (poll(&pfd, 1, secs * 1000) == 1 && read(w->rfd, &r, sizeof(r)) == sizeof(r)) {
		w->err = r.err;
		memcpy(w->buf, r.buf, sizeof(w->buf));
		ret = 0;
	} else {
		kill(w->pid, SIGKILL);
	}
	waitpid(w->pid, NULL, 0);
	close(w->rfd);
	atomic_store(&walker, 0);
	return ret;
}

FIXTURE(unlink_reval)
{
	char dir[64];
	int tfd;
};

FIXTURE_SETUP(unlink_reval)
{
	char opts[128];
	pthread_t t;
	int fd;

	self->tfd = -1;
	if (geteuid() != 0)
		SKIP(return, "need root to mount fuse");
	if (access("/dev/fuse", R_OK | W_OK))
		SKIP(return, "no /dev/fuse");

	ASSERT_EQ(0, unshare(CLONE_NEWNS));
	ASSERT_EQ(0, mount(NULL, "/", NULL, MS_REC | MS_PRIVATE, NULL));

	strcpy(self->dir, "/tmp/unlink_reval_XXXXXX");
	ASSERT_NE(NULL, mkdtemp(self->dir));
	ASSERT_EQ(0, mount("tmpfs", self->dir, "tmpfs", 0, "size=1M"));
	snprintf(fmnt, sizeof(fmnt), "%s/F", self->dir);
	snprintf(markpath, sizeof(markpath), "%s/mark", self->dir);
	ASSERT_EQ(0, mkdir(fmnt, 0755));
	fd = open(markpath, O_CREAT | O_WRONLY | O_CLOEXEC, 0644);
	ASSERT_GE(fd, 0);
	ASSERT_EQ((ssize_t)sizeof(MARK) - 1, write(fd, MARK, sizeof(MARK) - 1));
	close(fd);

	ffd = open("/dev/fuse", O_RDWR | O_CLOEXEC);
	ASSERT_GE(ffd, 0);
	snprintf(opts, sizeof(opts), "fd=%d,rootmode=40000,user_id=0,group_id=0,allow_other", ffd);
	ASSERT_EQ(0, mount("fuse", fmnt, "fuse", MS_NOSUID | MS_NODEV, opts));
	for (int i = 0; i < NR_SERVERS; i++)
		ASSERT_EQ(0, pthread_create(&t, NULL, server, NULL));
	ASSERT_EQ(0, pthread_create(&t, NULL, helper, NULL));
}

FIXTURE_TEARDOWN(unlink_reval)
{
	if (self->tfd >= 0)
		close(self->tfd);
	if (fmnt[0])
		umount2(fmnt, MNT_DETACH);
	if (self->dir[0]) {
		umount2(self->dir, MNT_DETACH);
		rmdir(self->dir);
	}
}

/* a copy of F with MARK mounted on f1 */
static int cover_f1(struct __test_metadata *_metadata)
{
	char buf[16] = {};
	struct stat st;
	int tfd, fd;

	atomic_store(&f1_present, 1);
	EXPECT_EQ(0, stat(fmnt, &st));
	tfd = syscall(SYS_open_tree, AT_FDCWD, fmnt, OPEN_TREE_CLONE | OPEN_TREE_CLOEXEC);
	EXPECT_GE(tfd, 0);
	/* f1 is in the dcache before the walker gets there */
	EXPECT_EQ(0, fstatat(tfd, "f1", &st, 0));
	EXPECT_EQ(0, cover(tfd, "f1"));
	fd = openat(tfd, "f1", O_RDONLY | O_CLOEXEC);
	EXPECT_GE(fd, 0);
	EXPECT_EQ((ssize_t)sizeof(MARK) - 1, read(fd, buf, sizeof(buf) - 1));
	EXPECT_STREQ(MARK, buf);
	close(fd);
	return tfd;
}

/*
 * The first readlink of lnk fails with ESTALE, so the open of F'/lnk is
 * repeated with LOOKUP_REVAL. In that walk f1 is unlinked while it is
 * revalidated, which detaches MARK.
 */
TEST_F(unlink_reval, reval_walk)
{
	for (int i = 0; i < 4; i++) {
		struct walk w = {};

		atomic_store(&f1_valid, 3600);
		self->tfd = cover_f1(_metadata);
		ASSERT_GE(self->tfd, 0);

		atomic_store(&unlink_f1, 1);
		ASSERT_EQ(0, walk_start(&w, self->tfd, "lnk", true));
		ASSERT_EQ(0, walk_wait(&w, WALK_SECS)) {
			TH_LOG("open() of F'/lnk did not return");
		}
		EXPECT_EQ(0, atomic_load(&unlink_f1)) {
			TH_LOG("f1 was never revalidated");
		}
		ASSERT_NE(0, w.err) {
			TH_LOG("round %d: read \"%s\" under the detached MARK", i, w.buf);
		}
		EXPECT_EQ(ENOENT, w.err);
		close(self->tfd);
		self->tfd = -1;
	}
}

/* The same in the walk without LOOKUP_REVAL. */
TEST_F(unlink_reval, ref_walk)
{
	for (int i = 0; i < 4; i++) {
		struct walk w = {};

		atomic_store(&f1_valid, 0);
		self->tfd = cover_f1(_metadata);
		ASSERT_GE(self->tfd, 0);

		atomic_store(&unlink_f1, 1);
		ASSERT_EQ(0, walk_start(&w, self->tfd, "f1", false));
		ASSERT_EQ(0, walk_wait(&w, WALK_SECS)) {
			TH_LOG("open() of F'/f1 did not return");
		}
		EXPECT_EQ(0, atomic_load(&unlink_f1)) {
			TH_LOG("f1 was never revalidated");
		}
		ASSERT_NE(0, w.err) {
			TH_LOG("round %d: read \"%s\" under the detached MARK", i, w.buf);
		}
		EXPECT_EQ(ENOENT, w.err);
		close(self->tfd);
		self->tfd = -1;
	}
}

/*
 * Every walk of F'/d/f finds a covered f that is unlinked while it is
 * revalidated: the revalidation of d has it looked up and covered again.
 * The open must neither read what MARK covered nor go on forever.
 */
TEST_F(unlink_reval, covered_name_keeps_going)
{
	struct walk w = {};
	struct stat st;

	ASSERT_EQ(0, stat(fmnt, &st));
	self->tfd = syscall(SYS_open_tree, AT_FDCWD, fmnt, OPEN_TREE_CLONE | OPEN_TREE_CLOEXEC);
	ASSERT_GE(self->tfd, 0);
	/* d is in the dcache, so the walker only ever revalidates it */
	ASSERT_EQ(0, fstatat(self->tfd, "d", &st, 0));

	atomic_store(&cover_tfd, self->tfd);
	atomic_store(&games, 1);
	ASSERT_EQ(0, walk_start(&w, self->tfd, "d/f", false));
	ASSERT_EQ(0, walk_wait(&w, WALK_SECS)) {
		atomic_store(&games, 0);
		TH_LOG("open() of F'/d/f still running after %ds and %ld unlinks",
		       WALK_SECS, atomic_load(&nr_unlinks));
	}
	atomic_store(&games, 0);
	EXPECT_GE(atomic_load(&nr_unlinks), 1);
	if (!w.err) {
		EXPECT_STREQ(MARK, w.buf) {
			TH_LOG("read \"%s\" under the detached MARK", w.buf);
		}
	}
}

/*
 * The walker revalidates d while a rename moves it to e. The server answers
 * that revalidation only after the rename went through, so the answer is
 * about a name the directory no longer has. The mounts below it have to
 * survive that: F'/e/f still has to show MARK.
 */
TEST_F(unlink_reval, renamed_dir_keeps_its_mounts)
{
	struct walk w = {};
	char buf[16] = {};
	struct stat st;
	int fd;

	ASSERT_EQ(0, stat(fmnt, &st));
	self->tfd = syscall(SYS_open_tree, AT_FDCWD, fmnt, OPEN_TREE_CLONE | OPEN_TREE_CLOEXEC);
	ASSERT_GE(self->tfd, 0);
	/* d and d/f are in the dcache, every walk revalidates d */
	ASSERT_EQ(0, fstatat(self->tfd, "d/f", &st, 0));
	ASSERT_EQ(0, cover(self->tfd, "d/f"));
	fd = openat(self->tfd, "d/f", O_RDONLY | O_CLOEXEC);
	ASSERT_GE(fd, 0);
	ASSERT_EQ((ssize_t)sizeof(MARK) - 1, read(fd, buf, sizeof(buf) - 1));
	ASSERT_STREQ(MARK, buf);
	close(fd);

	atomic_store(&rename_d, 1);
	ASSERT_EQ(0, walk_start(&w, self->tfd, "d/f", false));
	ASSERT_EQ(0, walk_wait(&w, WALK_SECS)) {
		TH_LOG("open() of F'/d/f did not return");
	}
	EXPECT_EQ(0, atomic_load(&rename_d)) {
		TH_LOG("d was never revalidated");
	}
	EXPECT_EQ(1, atomic_load(&d_is_e));
	EXPECT_EQ(ENOENT, w.err);

	/* the mounts below d went to e with it */
	memset(buf, 0, sizeof(buf));
	fd = openat(self->tfd, "e/f", O_RDONLY | O_CLOEXEC);
	ASSERT_GE(fd, 0);
	ASSERT_GT(read(fd, buf, sizeof(buf) - 1), 0);
	EXPECT_STREQ(MARK, buf) {
		TH_LOG("read \"%s\" below the renamed directory", buf);
	}
	close(fd);
}

/*
 * The server renames d to e behind our back: it answers the revalidation
 * of d with ENOENT and hands out d's node for e, no rename goes through
 * the mount. The directory would come back under a name its mounts never
 * covered, so the lookup of e is refused while the mark is below d. Once
 * the server calls it d again, d/f is back with the mark.
 */
TEST_F(unlink_reval, server_renamed_dir_is_busy)
{
	char buf[16] = {};
	struct stat st;
	int fd;

	ASSERT_EQ(0, stat(fmnt, &st));
	self->tfd = syscall(SYS_open_tree, AT_FDCWD, fmnt, OPEN_TREE_CLONE | OPEN_TREE_CLOEXEC);
	ASSERT_GE(self->tfd, 0);
	ASSERT_EQ(0, fstatat(self->tfd, "d/f", &st, 0));
	ASSERT_EQ(0, cover(self->tfd, "d/f"));

	atomic_store(&d_is_e, 1);
	EXPECT_EQ(-1, fstatat(self->tfd, "d/f", &st, 0));
	EXPECT_EQ(ENOENT, errno);
	fd = openat(self->tfd, "e/f", O_RDONLY | O_CLOEXEC);
	EXPECT_EQ(-1, fd) {
		TH_LOG("e/f opened although the mark would have moved along");
	}
	EXPECT_EQ(EBUSY, errno);
	if (fd >= 0)
		close(fd);

	atomic_store(&d_is_e, 0);
	fd = openat(self->tfd, "d/f", O_RDONLY | O_CLOEXEC);
	ASSERT_GE(fd, 0);
	ASSERT_GT(read(fd, buf, sizeof(buf) - 1), 0);
	EXPECT_STREQ(MARK, buf);
	close(fd);
}

/* The same without mounts: nothing to reveal, but it must end as well. */
TEST_F(unlink_reval, plain_name_keeps_going)
{
	struct walk w = {};
	struct stat st;
	char path[160];

	snprintf(path, sizeof(path), "%s/d/f", fmnt);
	ASSERT_EQ(0, fstatat(AT_FDCWD, fmnt, &st, 0));
	ASSERT_EQ(0, stat(path, &st));

	atomic_store(&games, 1);
	ASSERT_EQ(0, walk_start(&w, AT_FDCWD, path, false));
	ASSERT_EQ(0, walk_wait(&w, WALK_SECS)) {
		atomic_store(&games, 0);
		TH_LOG("open() of F/d/f still running after %ds and %ld unlinks",
		       WALK_SECS, atomic_load(&nr_unlinks));
	}
	atomic_store(&games, 0);
	EXPECT_GE(atomic_load(&nr_unlinks), 1);
	if (w.err) {
		EXPECT_EQ(ENOENT, w.err);
	}
}

/*
 * The server deletes d while MARK is mounted on d/f in a copy of F. The
 * mount goes and its trap stays on the copy, and the trap keeps d/f: a
 * server may go on answering for the names below a deleted directory
 * and a new dentry for d/f would be uncovered. So a walk from a
 * descriptor on d fails at d/f, and the notification is answered with
 * ENOTEMPTY since d still has a child.
 */
TEST_F(unlink_reval, deleted_dir_keeps_its_trap_below)
{
	struct stat st;
	int dfd;

	ASSERT_EQ(0, stat(fmnt, &st));
	self->tfd = syscall(SYS_open_tree, AT_FDCWD, fmnt, OPEN_TREE_CLONE | OPEN_TREE_CLOEXEC);
	ASSERT_GE(self->tfd, 0);
	dfd = openat(self->tfd, "d", O_PATH | O_DIRECTORY | O_CLOEXEC);
	ASSERT_GE(dfd, 0);
	ASSERT_EQ(0, fstatat(self->tfd, "d/f", &st, 0));
	ASSERT_EQ(0, cover(self->tfd, "d/f"));

	atomic_store(&d_present, 0);
	EXPECT_EQ(-ENOTEMPTY, notify_delete(ROOT_ID, D_ID, "d"));
	EXPECT_EQ(-1, fstatat(dfd, "f", &st, 0)) {
		TH_LOG("d/f is reachable through the deleted d");
	}
	EXPECT_EQ(ENOENT, errno);
	close(dfd);
}

/*
 * A delete notification for a node the name doesn't have is answered
 * with ENOENT and leaves the entry alone: d is invalidated, not removed,
 * and comes back with MARK still on d/f.
 */
TEST_F(unlink_reval, delete_of_the_wrong_node_keeps_mounts)
{
	char buf[16] = {};
	struct stat st;
	int fd;

	ASSERT_EQ(0, stat(fmnt, &st));
	self->tfd = syscall(SYS_open_tree, AT_FDCWD, fmnt, OPEN_TREE_CLONE | OPEN_TREE_CLOEXEC);
	ASSERT_GE(self->tfd, 0);
	ASSERT_EQ(0, fstatat(self->tfd, "d/f", &st, 0));
	ASSERT_EQ(0, cover(self->tfd, "d/f"));

	ASSERT_EQ(-ENOENT, notify_delete(ROOT_ID, 99, "d"));
	fd = openat(self->tfd, "d/f", O_RDONLY | O_CLOEXEC);
	ASSERT_GE(fd, 0) {
		TH_LOG("d/f lost its mark: %s", strerror(errno));
	}
	ASSERT_GT(read(fd, buf, sizeof(buf) - 1), 0);
	EXPECT_STREQ(MARK, buf);
	close(fd);
}

/*
 * The server deletes d, which has a directory mounted on it in a copy of
 * F, and hands its node out as e while a descriptor keeps the old dentry.
 * The trap the mount left is keyed to that dentry, so a lookup of e must
 * not move it along: e is busy until the descriptor goes. Then e is a
 * dentry of its own and works.
 */
TEST_F(unlink_reval, deleted_dir_handed_out_again_is_busy)
{
	char mdir[128], mfile[128], buf[16] = {};
	struct stat st;
	int dfd, fd;

	snprintf(mdir, sizeof(mdir), "%s/md", self->dir);
	snprintf(mfile, sizeof(mfile), "%s/md/f", self->dir);
	ASSERT_EQ(0, mkdir(mdir, 0755));
	fd = open(mfile, O_CREAT | O_WRONLY | O_CLOEXEC, 0644);
	ASSERT_GE(fd, 0);
	ASSERT_EQ((ssize_t)sizeof(MARK) - 1, write(fd, MARK, sizeof(MARK) - 1));
	close(fd);

	ASSERT_EQ(0, stat(fmnt, &st));
	self->tfd = syscall(SYS_open_tree, AT_FDCWD, fmnt, OPEN_TREE_CLONE | OPEN_TREE_CLOEXEC);
	ASSERT_GE(self->tfd, 0);
	/* the descriptor is on d itself, taken before the mount covers it */
	dfd = openat(self->tfd, "d", O_PATH | O_DIRECTORY | O_CLOEXEC);
	ASSERT_GE(dfd, 0);
	ASSERT_EQ(0, cover_from(self->tfd, mdir, "d"));
	fd = openat(self->tfd, "d/f", O_RDONLY | O_CLOEXEC);
	ASSERT_GE(fd, 0);
	ASSERT_GT(read(fd, buf, sizeof(buf) - 1), 0);
	ASSERT_STREQ(MARK, buf);
	close(fd);

	atomic_store(&d_present, 0);
	ASSERT_EQ(0, notify_delete(ROOT_ID, D_ID, "d"));
	atomic_store(&d_is_e, 1);
	EXPECT_EQ(-1, fstatat(self->tfd, "e", &st, 0)) {
		TH_LOG("e came back with the trap of d on it");
	}
	EXPECT_EQ(EBUSY, errno);

	close(dfd);
	/* the trap went with the dentry, e is a new one */
	EXPECT_EQ(0, fstatat(self->tfd, "e", &st, 0)) {
		TH_LOG("e is still refused: %s", strerror(errno));
	}
	atomic_store(&d_is_e, 0);
}

/* run @fn in a child and return its exit code */
static int in_child(int (*fn)(int, int), int a, int b)
{
	int status;
	pid_t pid;

	pid = fork();
	if (pid < 0)
		return -errno;
	if (!pid)
		_exit(fn(a, b));
	if (waitpid(pid, &status, 0) != pid)
		return -errno;
	return WIFEXITED(status) ? WEXITSTATUS(status) : -EIO;
}

enum { UNSHARE_REFUSED, UNSHARE_REVEALS, UNSHARE_WORKED, UNSHARE_OTHER };

/*
 * unshare(CLONE_NEWNS) with the cwd on @cwdfd and, if @rootfd is one, the
 * root on that, then what f in the root or cwd reads if it went through.
 */
static int unshare_from(int cwdfd, int rootfd)
{
	char buf[16] = {};
	int fd;

	if (rootfd >= 0 && (fchdir(rootfd) || chroot(".")))
		return UNSHARE_OTHER;
	if (fchdir(cwdfd))
		return UNSHARE_OTHER;
	if (unshare(CLONE_NEWNS))
		return errno == ENOENT ? UNSHARE_REFUSED : UNSHARE_OTHER;
	fd = open(rootfd >= 0 ? "/f" : "f", O_RDONLY | O_CLOEXEC);
	if (fd < 0)
		return UNSHARE_WORKED;
	if (read(fd, buf, sizeof(buf) - 1) < 0)
		return UNSHARE_OTHER;
	return strcmp(buf, UNDER) ? UNSHARE_WORKED : UNSHARE_REVEALS;
}

/*
 * unshare(CLONE_NEWNS) moves the cwd and the root of the task to the
 * copies of their mounts with the dentry, and a copy of a mount has none
 * of the covers the removed names on it left behind. From inside a
 * deleted directory with a trap below it the unshare is refused, and so
 * are a copy and a new mount namespace made from the directory with
 * open_tree(). From above the directory the unshare works with the
 * traps still on the mount, and so it does from a deleted directory on
 * a mount that has nothing to lose.
 */
TEST_F(unlink_reval, unshare_from_a_deleted_dir_fails)
{
	int ffd_dir, dfd, outfd, pfd, ret, err;
	char plain[128];
	struct stat st;

	ffd_dir = open(fmnt, O_PATH | O_DIRECTORY | O_CLOEXEC);
	ASSERT_GE(ffd_dir, 0);
	outfd = open(self->dir, O_PATH | O_DIRECTORY | O_CLOEXEC);
	ASSERT_GE(outfd, 0);
	ASSERT_EQ(0, stat(fmnt, &st));
	dfd = openat(ffd_dir, "d", O_PATH | O_DIRECTORY | O_CLOEXEC);
	ASSERT_GE(dfd, 0);
	ASSERT_EQ(0, fstatat(ffd_dir, "d/f", &st, 0));
	/* the cover goes on F itself, the mount the cwd and root are on */
	ASSERT_EQ(0, cover(ffd_dir, "d/f"));

	atomic_store(&d_present, 0);
	EXPECT_EQ(-ENOTEMPTY, notify_delete(ROOT_ID, D_ID, "d"));

	ret = in_child(unshare_from, dfd, -1);
	EXPECT_EQ(UNSHARE_REFUSED, ret) {
		TH_LOG("unshare from the deleted d %s", ret == UNSHARE_REVEALS ?
		       "went through and f reads what the mount covered" :
		       "didn't fail with ENOENT");
	}
	ret = in_child(unshare_from, outfd, dfd);
	EXPECT_EQ(UNSHARE_REFUSED, ret) {
		TH_LOG("unshare with the root on the deleted d %s", ret == UNSHARE_REVEALS ?
		       "went through and /f reads what the mount covered" :
		       "didn't fail with ENOENT");
	}

	/* the copies open_tree() makes from the directory */
	ret = syscall(SYS_open_tree, dfd, "", AT_EMPTY_PATH | OPEN_TREE_CLONE | OPEN_TREE_CLOEXEC);
	err = errno;
	EXPECT_EQ(-1, ret) {
		TH_LOG("open_tree(OPEN_TREE_CLONE) of the deleted d went through");
	}
	EXPECT_EQ(ENOENT, err);
	ret = syscall(SYS_open_tree, dfd, "", AT_EMPTY_PATH | OPEN_TREE_NAMESPACE | OPEN_TREE_CLOEXEC);
	err = errno;
	EXPECT_EQ(-1, ret) {
		TH_LOG("open_tree(OPEN_TREE_NAMESPACE) of the deleted d went through");
	}
	EXPECT_EQ(ENOENT, err);

	/* from above d the covers stay where they are and the copy is fine */
	EXPECT_EQ(UNSHARE_WORKED, in_child(unshare_from, ffd_dir, -1));

	/* a deleted directory on a mount without covers has nothing to lose */
	snprintf(plain, sizeof(plain), "%s/plain", self->dir);
	ASSERT_EQ(0, mkdir(plain, 0755));
	pfd = open(plain, O_PATH | O_DIRECTORY | O_CLOEXEC);
	ASSERT_GE(pfd, 0);
	ASSERT_EQ(0, rmdir(plain));
	EXPECT_EQ(UNSHARE_WORKED, in_child(unshare_from, pfd, -1));

	close(pfd);
	close(dfd);
	close(outfd);
	close(ffd_dir);
}

/* what a child with its cwd on d sees of d/f, step by step */
struct cwd_probe {
	int err[3];
	char buf[3][16];
	int unshare_err;
};

static void probe(struct cwd_probe *p, int step)
{
	int fd = open("f", O_RDONLY | O_CLOEXEC);

	if (fd < 0) {
		p->err[step] = errno;
		return;
	}
	if (read(fd, p->buf[step], sizeof(p->buf[step]) - 1) < 0)
		p->err[step] = errno;
	close(fd);
}

/*
 * The same for a task without privileges: the server deletes d while
 * MARK is mounted on d/f in F itself and a child has its cwd on d as
 * nobody. It reads MARK before the delete and is refused d/f after it.
 * Then it unshares its user and mount namespace, which anyone may do and
 * which would move its cwd to a copy of F without the trap. That is
 * refused as well, and if it ever goes through the copy must not show
 * what MARK covered.
 */
TEST_F(unlink_reval, unshare_from_a_deleted_dir_fails_for_nobody)
{
	int ready[2], go[2], res[2];
	char dpath[160], fpath[160];
	struct cwd_probe p = {};
	struct stat st;
	char c = 0;
	pid_t pid;

	snprintf(dpath, sizeof(dpath), "%s/d", fmnt);
	snprintf(fpath, sizeof(fpath), "%s/d/f", fmnt);
	ASSERT_EQ(0, stat(fpath, &st));
	ASSERT_EQ(0, mount(markpath, fpath, NULL, MS_BIND, NULL));

	ASSERT_EQ(0, pipe2(ready, O_CLOEXEC));
	ASSERT_EQ(0, pipe2(go, O_CLOEXEC));
	ASSERT_EQ(0, pipe2(res, O_CLOEXEC));
	pid = fork();
	ASSERT_GE(pid, 0);
	if (!pid) {
		/* nobody, with its cwd on d before d goes */
		if (setgroups(0, NULL) || setresgid(NOBODY, NOBODY, NOBODY) ||
		    setresuid(NOBODY, NOBODY, NOBODY) || chdir(dpath))
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

	atomic_store(&d_present, 0);
	EXPECT_EQ(-ENOTEMPTY, notify_delete(ROOT_ID, D_ID, "d"));
	ASSERT_EQ(1, write(go[1], &c, 1));
	ASSERT_EQ((ssize_t)sizeof(p), read(res[0], &p, sizeof(p)));
	waitpid(pid, NULL, 0);

	EXPECT_EQ(0, p.err[0]);
	EXPECT_STREQ(MARK, p.buf[0]);
	EXPECT_EQ(ENOENT, p.err[1]) {
		TH_LOG("d/f is reachable through the deleted d, read \"%s\"", p.buf[1]);
	}
	EXPECT_EQ(ENOENT, p.unshare_err) {
		if (p.unshare_err)
			TH_LOG("unshare(CLONE_NEWUSER | CLONE_NEWNS) as nobody: %s",
			       strerror(p.unshare_err));
		else
			TH_LOG("unshare(CLONE_NEWUSER | CLONE_NEWNS) as nobody went through, d/f in the copy: %s \"%s\"",
			       p.err[2] ? strerror(p.err[2]) : "opened", p.buf[2]);
	}
}

TEST_HARNESS_MAIN
