/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_SCHED_COREDUMP_H
#define _LINUX_SCHED_COREDUMP_H

#define SUID_DUMP_DISABLE	0	/* No setuid dumping */
#define SUID_DUMP_USER		1	/* Dump as user of process */
#define SUID_DUMP_ROOT		2	/* Dump as root */

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
