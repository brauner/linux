/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
#ifndef _UAPI_LINUX_CLOSE_RANGE_H
#define _UAPI_LINUX_CLOSE_RANGE_H

/* Unshare the file descriptor table before closing file descriptors. */
#define CLOSE_RANGE_UNSHARE	(1U << 1)

/* Set the FD_CLOEXEC bit instead of closing the file descriptor. */
#define CLOSE_RANGE_CLOEXEC	(1U << 2)

/*
 * Close every file descriptor with the FD_CLOEXEC bit set, except the ones
 * in the given range.
 */
#define CLOSE_RANGE_CLOEXEC_EXCEPT	(1U << 3)

#endif /* _UAPI_LINUX_CLOSE_RANGE_H */

