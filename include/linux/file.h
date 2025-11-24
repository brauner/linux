/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Wrapper functions for accessing the file_struct fd array.
 */

#ifndef __LINUX_FILE_H
#define __LINUX_FILE_H

#include <linux/compiler.h>
#include <linux/types.h>
#include <linux/posix_types.h>
#include <linux/errno.h>
#include <linux/cleanup.h>
#include <linux/err.h>

struct file;

extern void fput(struct file *);

struct file_operations;
struct task_struct;
struct vfsmount;
struct dentry;
struct inode;
struct path;
extern struct file *alloc_file_pseudo(struct inode *, struct vfsmount *,
	const char *, int flags, const struct file_operations *);
extern struct file *alloc_file_pseudo_noaccount(struct inode *, struct vfsmount *,
	const char *, int flags, const struct file_operations *);
extern struct file *alloc_file_clone(struct file *, int flags,
	const struct file_operations *);

/* either a reference to struct file + flags
 * (cloned vs. borrowed, pos locked), with
 * flags stored in lower bits of value,
 * or empty (represented by 0).
 */
struct fd {
	unsigned long word;
};
#define FDPUT_FPUT       1
#define FDPUT_POS_UNLOCK 2

#define fd_file(f) ((struct file *)((f).word & ~(FDPUT_FPUT|FDPUT_POS_UNLOCK)))
static inline bool fd_empty(struct fd f)
{
	return unlikely(!f.word);
}

#define EMPTY_FD (struct fd){0}
static inline struct fd BORROWED_FD(struct file *f)
{
	return (struct fd){(unsigned long)f};
}
static inline struct fd CLONED_FD(struct file *f)
{
	return (struct fd){(unsigned long)f | FDPUT_FPUT};
}

static inline void fdput(struct fd fd)
{
	if (unlikely(fd.word & FDPUT_FPUT))
		fput(fd_file(fd));
}

extern struct file *fget(unsigned int fd);
extern struct file *fget_raw(unsigned int fd);
extern struct file *fget_task(struct task_struct *task, unsigned int fd);
extern struct file *fget_task_next(struct task_struct *task, unsigned int *fd);
extern void __f_unlock_pos(struct file *);

struct fd fdget(unsigned int fd);
struct fd fdget_raw(unsigned int fd);
struct fd fdget_pos(unsigned int fd);

static inline void fdput_pos(struct fd f)
{
	if (f.word & FDPUT_POS_UNLOCK)
		__f_unlock_pos(fd_file(f));
	fdput(f);
}

DEFINE_CLASS(fd, struct fd, fdput(_T), fdget(fd), int fd)
DEFINE_CLASS(fd_raw, struct fd, fdput(_T), fdget_raw(fd), int fd)
DEFINE_CLASS(fd_pos, struct fd, fdput_pos(_T), fdget_pos(fd), int fd)

extern int f_dupfd(unsigned int from, struct file *file, unsigned flags);
extern int replace_fd(unsigned fd, struct file *file, unsigned flags);
extern void set_close_on_exec(unsigned int fd, int flag);
extern bool get_close_on_exec(unsigned int fd);
extern int __get_unused_fd_flags(unsigned flags, unsigned long nofile);
extern int get_unused_fd_flags(unsigned flags);
extern void put_unused_fd(unsigned int fd);

DEFINE_CLASS(get_unused_fd, int, if (_T >= 0) put_unused_fd(_T),
	     get_unused_fd_flags(flags), unsigned flags)
DEFINE_FREE(fput, struct file *, if (!IS_ERR_OR_NULL(_T)) fput(_T))

/*
 * take_fd() will take care to set @fd to -EBADF ensuring that
 * CLASS(get_unused_fd) won't call put_unused_fd(). This makes it
 * easier to rely on CLASS(get_unused_fd):
 *
 * struct file *f;
 *
 * CLASS(get_unused_fd, fd)(O_CLOEXEC);
 * if (fd < 0)
 *         return fd;
 *
 * f = dentry_open(&path, O_RDONLY, current_cred());
 * if (IS_ERR(f))
 *         return PTR_ERR(f);
 *
 * fd_install(fd, f);
 * return take_fd(fd);
 */
#define take_fd(fd) __get_and_null(fd, -EBADF)

extern void fd_install(unsigned int fd, struct file *file);

int receive_fd(struct file *file, int __user *ufd, unsigned int o_flags);

int receive_fd_replace(int new_fd, struct file *file, unsigned int o_flags);

extern void flush_delayed_fput(void);
extern void __fput_sync(struct file *);

extern unsigned int sysctl_nr_open_min, sysctl_nr_open_max;

/*
 * Sentinel value for fd_prepare.__file indicating file not yet claimed.
 * This is distinct from NULL (allocation returned NULL), ERR_PTR (allocation
 * failed), and valid pointers. Using address 1 which is guaranteed to be:
 * - Not NULL (0x0)
 * - Not in ERR_PTR range (typically -4095 to -1)
 * - Not a valid kernel pointer
 */
#define FD_FILE_UNCLAIMED ((struct file *)1UL)

/*
 * class_fd_prepare_t: Combined fd + file allocation cleanup class.
 *
 * Allocates an fd and a file together. On error paths, automatically cleans
 * up whichever resource was successfully allocated. Allows flexible file
 * allocation with different functions per usage.
 */
typedef struct {
	s32 err;
	s32 __fd;
	struct file *__file;
} class_fd_prepare_t;

#define fd_prepare_fd(_T) ((_T).__fd)
#define fd_prepare_file(_T) ((_T).__file)

static inline void class_fd_prepare_destructor(class_fd_prepare_t *_T)
{
	if (unlikely(_T->err)) {
		if (likely(_T->__fd >= 0))
			put_unused_fd(_T->__fd);
		if (unlikely(!IS_ERR_OR_NULL(_T->__file) &&
			     _T->__file != FD_FILE_UNCLAIMED))
			fput(_T->__file);
	}
}

static inline int class_fd_prepare_lock_err(class_fd_prepare_t *_T)
{
	if (unlikely(_T->__fd < 0))
		return _T->__fd;
	if (unlikely(IS_ERR(_T->__file)))
		return PTR_ERR(_T->__file);
	if (unlikely(!_T->__file))
		return -ENOMEM;
	return 0;
}

/*
 * __FD_PREPARE_INIT(fd_flags, file_init_expr):
 *     Helper to initialize fd_prepare class with both fd and file.
 * @fd_flags: flags for get_unused_fd_flags()
 * @file_init_expr: expression that returns struct file *
 *
 * Returns a struct fd_prepare with fd, file, and err set.
 * If fd allocation fails, fd will be negative and err will be set.
 * If fd succeeds but file_init_expr fails, file will be ERR_PTR and err will be set.
 * The err field is the single source of truth for error checking.
 */
#define __FD_PREPARE_INIT(_fd_flags, _file_init_owned)                   \
	({                                                               \
		class_fd_prepare_t _fd_prepare = {                       \
			.__fd = get_unused_fd_flags((_fd_flags)),        \
		};                                                       \
		if (likely(_fd_prepare.__fd >= 0))                       \
			_fd_prepare.__file = (_file_init_owned);         \
		_fd_prepare.err = ACQUIRE_ERR(fd_prepare, &_fd_prepare); \
		_fd_prepare;                                             \
	})

/*
 * FD_PREPARE(var, fd_flags[, file_init_owned]):
 *     Declares and initializes an fd_prepare variable with automatic cleanup.
 *     No separate scope required - cleanup happens when variable goes out of scope.
 *
 * Two forms:
 *   FD_PREPARE(var, fd_flags) - allocates only fd, use FD_FILE_CLAIM() to set file later
 *   FD_PREPARE(var, fd_flags, file_expr) - allocates both fd and file together
 *
 * @_var: name of struct fd_prepare variable to define
 * @_fd_flags: flags for get_unused_fd_flags()
 * @_file_init_owned: (optional) struct file to take ownership of (can be expression)
 */
#define __FD_PREPARE_2(_var, _fd_flags) \
	CLASS_INIT(fd_prepare, _var, __FD_PREPARE_INIT(_fd_flags, FD_FILE_UNCLAIMED))

#define __FD_PREPARE_3(_var, _fd_flags, _file_init_owned) \
	CLASS_INIT(fd_prepare, _var, __FD_PREPARE_INIT(_fd_flags, _file_init_owned))

#define __FD_PREPARE_CHOOSE(_var, _fd_flags, _file_init_owned, NAME, ...) NAME

#define FD_PREPARE(X...) CONCATENATE(__FD_PREPARE_, COUNT_ARGS(X))(X)

#define FD_FILE_CLAIM(_fd_prepare, _file_init_owned)                \
	({                                                          \
		class_fd_prepare_t *__p = &(_fd_prepare);           \
		VFS_WARN_ON_ONCE(__p->__fd < 0);                    \
		VFS_WARN_ON_ONCE(__p->__file != FD_FILE_UNCLAIMED); \
		__p->__file = (_file_init_owned);                   \
		__p->err = ACQUIRE_ERR(fd_prepare, __p);            \
		__p->err;                                           \
	})

#define fd_publish(_fd_prepare)                                     \
	({                                                          \
		class_fd_prepare_t *__p = &(_fd_prepare);           \
		VFS_WARN_ON_ONCE(__p->err);                         \
		VFS_WARN_ON_ONCE(__p->__fd < 0);                    \
		VFS_WARN_ON_ONCE(IS_ERR_OR_NULL(__p->__file));      \
		VFS_WARN_ON_ONCE(__p->__file == FD_FILE_UNCLAIMED); \
		fd_install(__p->__fd, __p->__file);                 \
		retain_and_null_ptr(__p->__file);                   \
		take_fd(__p->__fd);                                 \
	})

#define FD_ADD(_fd_flags, _file_init_owned)                    \
	({                                                     \
		FD_PREPARE(_var, _fd_flags, _file_init_owned); \
		s32 ret = _var.err;                            \
		if (likely(!ret))                              \
			ret = fd_publish(_var);                \
		ret;                                           \
	})

#endif /* __LINUX_FILE_H */
