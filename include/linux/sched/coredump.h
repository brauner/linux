/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_SCHED_COREDUMP_H
#define _LINUX_SCHED_COREDUMP_H

/*
 * Task dumpability mode.
 *
 * Stored in task->exec_state->dumpable, this gates two things:
 *
 *   1. Whether the kernel will produce a core dump for the task.
 *   2. Whether other processes are permitted to attach to it via
 *      ptrace() based on credentials alone (i.e. without holding
 *      CAP_SYS_PTRACE in the task's exec-time user_ns).
 *
 * The integer values are stable userspace ABI: they are exposed via
 * /proc/sys/fs/suid_dumpable and via prctl(PR_SET_DUMPABLE).  Do not
 * renumber.
 */
enum task_dumpable {
	/*
	 * No core dump is produced and only a tracer with CAP_SYS_PTRACE
	 * in the task's exec-time user_ns may attach.  This is the
	 * post-setuid state when /proc/sys/fs/suid_dumpable = 0 and the
	 * effective state set by prctl(PR_SET_DUMPABLE, 0).
	 */
	TASK_DUMPABLE_OFF	= 0,

	/*
	 * Default state for newly exec'd processes.  Core dumps are
	 * produced and ptrace is permitted to processes running as the
	 * same user (subject to YAMA / other LSMs).
	 */
	TASK_DUMPABLE_OWNER	= 1,

	/*
	 * Restricted dump: the core file is created owned by root and
	 * lives in a path that only root can read.  Used after a setuid
	 * privilege transition when /proc/sys/fs/suid_dumpable = 2.
	 * ptrace requires CAP_SYS_PTRACE, the same as TASK_DUMPABLE_OFF.
	 */
	TASK_DUMPABLE_ROOT	= 2,
};

struct task_struct;

/*
 * Dumpability is per-task state (stored in task->exec_state).  It is set
 * by execve() and refined by commit_creds()/prctl(PR_SET_DUMPABLE).
 * Reading the value through these accessors is safe at any point during
 * the task's lifetime, including after exit_mm() has cleared task->mm.
 */
void set_dumpable(struct task_struct *task, int value);
int get_dumpable(struct task_struct *task);

#endif /* _LINUX_SCHED_COREDUMP_H */
