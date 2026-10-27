// SPDX-License-Identifier: GPL-2.0
/*
 * io_uring issues a read or write to a blocking tty inline once poll
 * reports the tty ready. The inline attempt must not sleep in
 * io_uring_enter(), even when the request can't complete at once.
 */

#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <linux/io_uring.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <termios.h>
#include <time.h>
#include <unistd.h>

#include "../kselftest_harness.h"

#define WRITE_SIZE (64 * 1024)

struct uring {
	int fd;
	unsigned int *sq_tail, *sq_mask, *sq_array;
	unsigned int *cq_head, *cq_tail, *cq_mask;
	struct io_uring_sqe *sqes;
	struct io_uring_cqe *cqes;
};

static int uring_setup(struct uring *r)
{
	struct io_uring_params p = {};
	void *sq, *cq;

	r->fd = syscall(__NR_io_uring_setup, 4, &p);
	if (r->fd < 0)
		return -errno;

	sq = mmap(NULL, p.sq_off.array + p.sq_entries * sizeof(unsigned int),
		  PROT_READ | PROT_WRITE, MAP_SHARED | MAP_POPULATE, r->fd,
		  IORING_OFF_SQ_RING);
	cq = mmap(NULL, p.cq_off.cqes + p.cq_entries * sizeof(struct io_uring_cqe),
		  PROT_READ | PROT_WRITE, MAP_SHARED | MAP_POPULATE, r->fd,
		  IORING_OFF_CQ_RING);
	r->sqes = mmap(NULL, p.sq_entries * sizeof(struct io_uring_sqe),
		       PROT_READ | PROT_WRITE, MAP_SHARED | MAP_POPULATE, r->fd,
		       IORING_OFF_SQES);
	if (sq == MAP_FAILED || cq == MAP_FAILED || r->sqes == MAP_FAILED)
		return -ENOMEM;

	r->sq_tail = sq + p.sq_off.tail;
	r->sq_mask = sq + p.sq_off.ring_mask;
	r->sq_array = sq + p.sq_off.array;
	r->cq_head = cq + p.cq_off.head;
	r->cq_tail = cq + p.cq_off.tail;
	r->cq_mask = cq + p.cq_off.ring_mask;
	r->cqes = cq + p.cq_off.cqes;
	return 0;
}

static void uring_queue(struct uring *r, int op, int fd, void *buf,
			unsigned int len)
{
	unsigned int tail = *r->sq_tail, idx = tail & *r->sq_mask;
	struct io_uring_sqe *sqe = &r->sqes[idx];

	memset(sqe, 0, sizeof(*sqe));
	sqe->opcode = op;
	sqe->fd = fd;
	sqe->addr = (unsigned long)buf;
	sqe->len = len;
	sqe->off = -1;
	r->sq_array[idx] = idx;
	__atomic_store_n(r->sq_tail, tail + 1, __ATOMIC_RELEASE);
}

static bool uring_reap(struct uring *r, int *res)
{
	unsigned int head = *r->cq_head;

	if (head == __atomic_load_n(r->cq_tail, __ATOMIC_ACQUIRE))
		return false;
	*res = r->cqes[head & *r->cq_mask].res;
	__atomic_store_n(r->cq_head, head + 1, __ATOMIC_RELEASE);
	return true;
}

static double now(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);
	return ts.tv_sec + ts.tv_nsec / 1e9;
}

static void on_alarm(int sig)
{
}

/*
 * Submit the queued request without waiting for it. A kernel that sleeps
 * in the tty would block here forever, so a SIGALRM interrupts the sleep
 * after two seconds.
 */
static double uring_submit_timed(struct uring *r)
{
	struct sigaction sa = { .sa_handler = on_alarm };
	double start, elapsed;
	int ret;

	sigaction(SIGALRM, &sa, NULL);
	alarm(2);
	start = now();
	ret = syscall(__NR_io_uring_enter, r->fd, 1, 0, 0, NULL, 0);
	elapsed = now() - start;
	alarm(0);
	return ret == 1 ? elapsed : -1;
}

FIXTURE(pty) {
	int master;
	int slave;
	struct uring ring;
	char buf[WRITE_SIZE];
};

FIXTURE_SETUP(pty)
{
	struct termios t;
	int ret;

	self->master = posix_openpt(O_RDWR | O_NOCTTY);
	ASSERT_GE(self->master, 0);
	ASSERT_EQ(grantpt(self->master), 0);
	ASSERT_EQ(unlockpt(self->master), 0);
	self->slave = open(ptsname(self->master), O_RDWR | O_NOCTTY);
	ASSERT_GE(self->slave, 0);

	ASSERT_EQ(tcgetattr(self->slave, &t), 0);
	cfmakeraw(&t);
	ASSERT_EQ(tcsetattr(self->slave, TCSANOW, &t), 0);

	memset(self->buf, 'x', sizeof(self->buf));

	ret = uring_setup(&self->ring);
	if (ret == -ENOSYS || ret == -EPERM)
		SKIP(return, "io_uring is not available");
	ASSERT_EQ(ret, 0);
}

FIXTURE_TEARDOWN(pty)
{
	close(self->ring.fd);
	close(self->slave);
	close(self->master);
}

/* Drain the master until the request completes, for up to five seconds. */
static bool drain_until_complete(int master, struct uring *r, int *res)
{
	static char sink[WRITE_SIZE];
	double start = now();

	fcntl(master, F_SETFL, O_NONBLOCK);
	while (now() - start < 5) {
		if (read(master, sink, sizeof(sink)) < 0 && errno != EAGAIN)
			return false;
		syscall(__NR_io_uring_enter, r->fd, 0, 0, IORING_ENTER_GETEVENTS,
			NULL, 0);
		if (uring_reap(r, res))
			return true;
		usleep(10000);
	}
	return false;
}

/* The write is larger than the room in the pty and the master isn't read. */
TEST_F(pty, write_larger_than_room)
{
	double elapsed;
	int res;

	uring_queue(&self->ring, IORING_OP_WRITE, self->slave, self->buf,
		    WRITE_SIZE);
	elapsed = uring_submit_timed(&self->ring);
	ASSERT_GE(elapsed, 0);
	EXPECT_LT(elapsed, 1);

	ASSERT_TRUE(drain_until_complete(self->master, &self->ring, &res));
	EXPECT_GT(res, 0);
	EXPECT_LE(res, WRITE_SIZE);
}

/* Without room, the write waits for the master to be read. */
TEST_F(pty, write_without_room)
{
	double elapsed;
	int nb, res;

	nb = open(ptsname(self->master), O_RDWR | O_NOCTTY | O_NONBLOCK);
	ASSERT_GE(nb, 0);
	while (write(nb, self->buf, sizeof(self->buf)) > 0)
		;
	ASSERT_EQ(errno, EAGAIN);
	close(nb);

	uring_queue(&self->ring, IORING_OP_WRITE, self->slave, self->buf, 16);
	elapsed = uring_submit_timed(&self->ring);
	ASSERT_GE(elapsed, 0);
	EXPECT_LT(elapsed, 1);
	EXPECT_FALSE(uring_reap(&self->ring, &res));

	ASSERT_TRUE(drain_until_complete(self->master, &self->ring, &res));
	EXPECT_EQ(res, 16);
}

/*
 * With VTIME set, poll reports input after one byte, while a blocking read
 * waits for VMIN bytes until the inter-byte timer expires.
 */
TEST_F(pty, read_with_vmin_and_vtime)
{
	struct termios t;
	double elapsed;
	int res;

	ASSERT_EQ(tcgetattr(self->slave, &t), 0);
	t.c_cc[VMIN] = 4;
	t.c_cc[VTIME] = 20;
	ASSERT_EQ(tcsetattr(self->slave, TCSANOW, &t), 0);
	ASSERT_EQ(write(self->master, "a", 1), 1);
	usleep(100000);

	uring_queue(&self->ring, IORING_OP_READ, self->slave, self->buf, 4);
	elapsed = uring_submit_timed(&self->ring);
	ASSERT_GE(elapsed, 0);
	EXPECT_LT(elapsed, 1);

	ASSERT_EQ(write(self->master, "bcd", 3), 3);
	ASSERT_TRUE(drain_until_complete(self->master, &self->ring, &res));
	EXPECT_GT(res, 0);
	EXPECT_LE(res, 4);
}

TEST_HARNESS_MAIN
