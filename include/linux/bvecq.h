/* SPDX-License-Identifier: GPL-2.0 */
/* Implementation of a segmented queue of bio_vec[].
 *
 * Copyright (C) 2026 Red Hat, Inc. All Rights Reserved.
 * Written by David Howells (dhowells@redhat.com)
 */

#ifndef _LINUX_BVECQ_H
#define _LINUX_BVECQ_H

#include <linux/bvec.h>

/*
 * The type of memory retention used by the elements in bvecq->bv[] and how to
 * clean it up.
 */
enum bvecq_mem {
	BVECQ_MEM_EXTERNAL,	/* Externally retained memory - no freeing */
	BVECQ_MEM_PAGECACHE,	/* Ref'd pagecache pages - must put */
	BVECQ_MEM_GUP,		/* Pinned memory from get_user_pages() - unpin */
	BVECQ_MEM_ALLOCED,	/* Memory alloc'd by bvecq - can be freed/pooled */
} __mode(byte);

/*
 * Segmented bio_vec queue.
 *
 * These can be linked together to form messages of indefinite length and
 * iterated over with an ITER_BVECQ iterator.  The list is non-circular; next
 * and prev are NULL at the ends.
 *
 * The bv pointer points to the bio_vec array; this may be __bv if allocated
 * together.  The caller is responsible for determining whether or not this is
 * the case as the array pointed to by bv may be follow on directly from the
 * bvecq by accident of allocation (ie. ->bv == ->__bv is *not* sufficient to
 * determine this).
 */
struct bvecq {
	struct bvecq	*next;		/* Next bvec in the list or NULL */
	struct bvecq	*prev;		/* Prev bvec in the list or NULL */
	refcount_t	ref;
	u32		priv;		/* Private data */
	u16		nr_slots;	/* Number of elements in bv[] used */
	u16		max_slots;	/* Number of elements allocated in bv[] */
	enum bvecq_mem	mem_type:3;	/* What sort of memory and how to free it */
	bool		inline_bv:1;	/* T if __bv[] is being used */
	struct bio_vec	*bv;		/* Pointer to array of page fragments */
	struct bio_vec	__bv[];		/* Default array (if ->inline_bv) */
};

#endif /* _LINUX_BVECQ_H */
