/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_SCHED_EXEC_STATE_H
#define _LINUX_SCHED_EXEC_STATE_H

#include <linux/refcount.h>
#include <linux/sched/coredump.h>

struct task_struct;
struct user_namespace;

/*
 * struct task_exec_state - state established at execve()
 *
 * Holds bits of state that are set when a task last ran through execve(),
 * that need to remain readable for the rest of the task's lifetime -
 * specifically, after the task has gone through exit_mm() and task->mm
 * has been cleared.  The classic case is __ptrace_may_access() walking
 * a zombie task: task->mm is NULL, so the original mm-based storage for
 * dumpability and user_ns is unreachable.  task_exec_state is reachable
 * through task->exec_state until free_task() drops the last reference,
 * so these reads stay valid until the very end of task lifetime.
 *
 * Sharing mirrors mm sharing: tasks created with CLONE_VM share a single
 * task_exec_state with their parent, so dumpability and user_ns updates
 * propagate across CLONE_VM peers (in particular all threads of a thread
 * group) atomically, the same way they did when these fields lived in
 * mm->flags / mm->user_ns.  execve() always allocates a fresh state via
 * replace_task_exec_state() and drops the reference on the old one.
 *
 * @count:     refcount; one per task that points at this state.
 * @dumpable:  SUID_DUMP_* set by execve() and refined by commit_creds().
 * @user_ns:   the user namespace the task was running in at last execve(),
 *             possibly narrowed by would_dump() to contain the binary.
 *             Owns a reference released when @count reaches zero.
 *
 * Other exec-time state (exe_file, saved_auxv, ...) is a natural fit for
 * this struct and is expected to migrate here in follow-up changes.
 */
struct task_exec_state {
	refcount_t		count;
	int			dumpable;
	struct user_namespace	*user_ns;
};

struct task_exec_state *alloc_task_exec_state(struct user_namespace *user_ns);
struct task_exec_state *dup_task_exec_state(const struct task_exec_state *old);
void put_task_exec_state(struct task_exec_state *es);

/*
 * Replace task->exec_state with @new and drop the reference on the old
 * one.  Called from the execve() path with task->signal->exec_update_lock
 * held for write.
 */
void replace_task_exec_state(struct task_struct *task,
			     struct task_exec_state *new);

/*
 * task_exec_user_ns - the user_namespace pinned at the task's last execve().
 *
 * Always returns a valid user_namespace.  Falls back to &init_user_ns for
 * the very early init/kthread path before any task has run execve().
 */
struct user_namespace *task_exec_user_ns(struct task_struct *task);

#endif /* _LINUX_SCHED_EXEC_STATE_H */
