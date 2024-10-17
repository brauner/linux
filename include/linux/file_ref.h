/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef _LINUX_FILE_REF_H
#define _LINUX_FILE_REF_H

#include <linux/atomic.h>
#include <linux/preempt.h>
#include <linux/types.h>

#ifdef CONFIG_64BIT
#define FILE_REF_ONEREF		0x0000000000000000UL
#define FILE_REF_MAXREF		0x7FFFFFFFFFFFFFFFUL
#define FILE_REF_SATURATED	0xA000000000000000UL
#define FILE_REF_RELEASED	0xC000000000000000UL
#define FILE_REF_DEAD		0xE000000000000000UL
#define FILE_REF_NOREF		0xFFFFFFFFFFFFFFFFUL
#else
#define FILE_REF_ONEREF		0x00000000U
#define FILE_REF_MAXREF		0x7FFFFFFFU
#define FILE_REF_SATURATED	0xA0000000U
#define FILE_REF_RELEASED	0xC0000000U
#define FILE_REF_DEAD		0xE0000000U
#define FILE_REF_NOREF		0xFFFFFFFFU
#endif

typedef struct {
#ifdef CONFIG_64BIT
	atomic64_t refcnt;
#else
	atomic_t refcnt;
#endif
} file_ref_t;

/**
 * file_ref_init - Initialize a file reference count
 * @ref: Pointer to the reference count
 * @cnt: The initial reference count typically '1'
 */
static inline void file_ref_init(file_ref_t *ref, unsigned long cnt)
{
	atomic_long_set(&ref->refcnt, cnt - 1);
}

bool __file_ref_put(file_ref_t *ref, unsigned long cnt);

/**
 * file_ref_get - Acquire one reference on a file
 * @ref: Pointer to the reference count
 *
 * Similar to atomic_inc_not_zero() but saturates at FILE_REF_MAXREF.
 *
 * Provides full memory ordering.
 *
 * Return: False if the attempt to acquire a reference failed. This happens
 *         when the last reference has been put already. True if a reference
 *         was successfully acquired
 */
static __always_inline __must_check bool file_ref_get(file_ref_t *ref)
{
	/*
	 * Unconditionally increase the reference count with full
	 * ordering. The saturation and dead zones provide enough
	 * tolerance for this.
	 */
	return !atomic_long_add_negative(1, &ref->refcnt);
}

/**
 * file_ref_put -- Release a file reference
 * @ref:	Pointer to the reference count
 *
 * Provides release memory ordering, such that prior loads and stores
 * are done before, and provides an acquire ordering on success such
 * that free() must come after.
 *
 * Return: True if this was the last reference with no future references
 *         possible. This signals the caller that it can safely release
 *         the object which is protected by the reference counter.
 *         False if there are still active references or the put() raced
 *         with a concurrent get()/put() pair. Caller is not allowed to
 *         release the protected object.
 */
static __always_inline __must_check bool file_ref_put(file_ref_t *ref)
{
	long cnt;

	guard(preempt)();
	/*
	 * Unconditionally decrease the reference count. The saturation
	 * and dead zones provide enough tolerance for this. If this
	 * fails then we need to handle the last reference drop and
	 * cases inside the saturation and dead zones.
	 */
	cnt = atomic_long_dec_return(&ref->refcnt);
	if (cnt >= 0)
		return false;
	return __file_ref_put(ref, cnt);
}

/**
 * file_ref_read - Read the number of file references
 * @ref: Pointer to the reference count
 *
 * Return: The number of held references (0 ... N)
 */
static inline unsigned long file_ref_read(file_ref_t *ref)
{
	unsigned long c = atomic_long_read(&ref->refcnt);

	/* Return 0 if within the DEAD zone. */
	return c >= FILE_REF_RELEASED ? 0 : c + 1;
}

#endif
