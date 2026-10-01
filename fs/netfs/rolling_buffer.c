// SPDX-License-Identifier: GPL-2.0-or-later
/* Rolling buffer helpers
 *
 * Copyright (C) 2024 Red Hat, Inc. All Rights Reserved.
 * Written by David Howells (dhowells@redhat.com)
 */

#include <linux/bitops.h>
#include <linux/mempool.h>
#include <linux/pagemap.h>
#include <linux/rolling_buffer.h>
#include <linux/slab.h>
#include "internal.h"

static atomic_t debug_ids;

/**
 * netfs_folioq_alloc - Allocate a folio_queue struct
 * @rreq_id: Associated debugging ID for tracing purposes
 * @gfp: Allocation constraints
 * @trace: Trace tag to indicate the purpose of the allocation
 *
 * Allocate, initialise and account the folio_queue struct and log a trace line
 * to mark the allocation.
 */
struct folio_queue *netfs_folioq_alloc(unsigned int rreq_id, gfp_t gfp,
				       unsigned int /*enum netfs_folioq_trace*/ trace)
{
	struct folio_queue *fq;

	if (gfp == GFP_KERNEL)
		fq = mempool_alloc_noreserve(&netfs_folioq_pool, gfp);
	else
		fq = mempool_alloc(&netfs_folioq_pool, gfp);
	if (fq) {
		netfs_stat(&netfs_n_folioq);
		folioq_init(fq, rreq_id);
		fq->debug_id = atomic_inc_return(&debug_ids);
		trace_netfs_folioq(fq, trace);
	}
	return fq;
}
EXPORT_SYMBOL(netfs_folioq_alloc);

/**
 * netfs_folioq_free - Free a folio_queue struct
 * @folioq: The object to free
 * @trace: Trace tag to indicate which free
 *
 * Free and unaccount the folio_queue struct.
 */
void netfs_folioq_free(struct folio_queue *folioq,
		       unsigned int /*enum netfs_trace_folioq*/ trace)
{
	trace_netfs_folioq(folioq, trace);
	netfs_stat_d(&netfs_n_folioq);
	mempool_free(folioq, &netfs_folioq_pool);
}
EXPORT_SYMBOL(netfs_folioq_free);

/*
 * Initialise a rolling buffer.  We allocate an empty folio queue struct to so
 * that the pointers can be independently driven by the producer and the
 * consumer.
 */
int rolling_buffer_init(struct rolling_buffer *roll, unsigned int direction,
			gfp_t gfp, bool for_writeback)
{
	struct bvecq *bq;

	roll->for_writeback = for_writeback;

	bq = bvecq_alloc_one(BVECQ_POOL_SLOTS, gfp, for_writeback);
	if (!bq)
		return -ENOMEM;

	roll->head = bq;
	roll->tail = bq;
	iov_iter_bvec_queue(&roll->iter, direction, bq, 0, 0, 0);
	return 0;
}

/*
 * Add another bvecq to a rolling buffer if there's no space left.
 */
int rolling_buffer_make_space(struct rolling_buffer *roll, gfp_t gfp)
{
	struct bvecq *bq, *head = roll->head;

	if (!bvecq_is_full(head))
		return 0;

	bq = bvecq_alloc_one(BVECQ_POOL_SLOTS, gfp, roll->for_writeback);
	if (!bq)
		return -ENOMEM;

	roll->head = bq;
	if (bvecq_is_full(head)) {
		/* Make sure we don't leave the master iterator pointing to a
		 * block that might get immediately consumed.
		 */
		if (roll->iter.bvecq == head &&
		    roll->iter.bvecq_slot == head->nr_slots) {
			roll->iter.bvecq = bq;
			roll->iter.bvecq_slot = 0;
		}
	}

	/* Make sure the initialisation is stored before the next pointer.
	 *
	 * [!] NOTE: After we set head->next, the consumer is at liberty to
	 * immediately delete the old head.
	 */
	bvecq_append(head, bq);
	return 0;
}

/*
 * Decant the entire list of folios to read into a rolling buffer.
 */
ssize_t rolling_buffer_bulk_load_from_ra(struct rolling_buffer *roll,
					 struct readahead_control *ractl,
					 gfp_t gfp)
{
	struct bvecq *bq;
	size_t loaded = 0;

	while (ractl->_nr_pages - ractl->_batch_count > 0) {
		struct page **pages;
		unsigned int nr;

		/* Allocate a bvecq to put some folios into and attach it to
		 * the rolling buffer.
		 */
		bq = bvecq_alloc_one(BVECQ_POOL_SLOTS, gfp, false);
		if (!bq)
			goto nomem_unlock;
		bq->mem_type = BVECQ_MEM_EXTERNAL; /* Folio cleanup handled separately. */

		if (!roll->tail)
			roll->tail = bq;
		else
			bvecq_append(roll->head, bq);
		roll->head = bq;

		/* Get a bunch of folios and note their sizes. */
		pages = (struct page **)(bq->bv + bq->max_slots);
		pages -= bq->max_slots;
		nr = __readahead_batch(ractl, pages, bq->max_slots);
		if (WARN_ON_ONCE(!nr))
			break;

		for (int slot = 0; slot < nr; slot++) {
			struct folio *folio = page_folio(pages[slot]);
			size_t len = folio_size(folio);

			bvec_set_folio(&bq->bv[slot], folio, len, 0);
			loaded += len;
			trace_netfs_folio(folio, netfs_folio_trace_read);
		}

		bvecq_filled_to(bq, nr);
	}

	WRITE_ONCE(roll->iter.count, loaded);
	iov_iter_bvec_queue(&roll->iter, ITER_DEST, roll->tail, 0, 0, loaded);
	return loaded;

nomem_unlock:
	for (bq = roll->tail; bq; bq = bq->next) {
		for (int slot = 0; slot < bq->nr_slots; slot++) {
			struct folio *folio = bvec_folio(&bq->bv[slot]);

			folio_unlock(folio);
			folio_put(folio);
		}
	}
	rolling_buffer_clear(roll);
	roll->head = NULL;
	roll->tail = NULL;
	return -ENOMEM;
}

/*
 * Append a folio to the rolling buffer.
 */
ssize_t rolling_buffer_append(struct rolling_buffer *roll, struct folio *folio,
			      gfp_t gfp)
{
	ssize_t size = folio_size(folio);
	int slot;

	if (rolling_buffer_make_space(roll, gfp) < 0)
		return -ENOMEM;

	slot = roll->head->nr_slots;
	bvec_set_folio(&roll->head->bv[slot], folio, size, 0);
	bvecq_filled_to(roll->head, slot + 1);

	WRITE_ONCE(roll->iter.count, roll->iter.count + size);
	return size;
}

/*
 * Delete a spent buffer from a rolling queue and return the next in line.  We
 * don't return the last buffer to keep the pointers independent, but return
 * NULL instead.
 */
struct bvecq *rolling_buffer_delete_spent(struct rolling_buffer *roll)
{
	struct bvecq *spent = roll->tail, *next = bvecq_next(spent);

	if (!next)
		return NULL;
	next->prev = NULL;
	roll->tail = next;
	spent->next = NULL;
	bvecq_put(spent);
	return next;
}

/*
 * Clear out a rolling queue.
 */
void rolling_buffer_clear(struct rolling_buffer *roll)
{
	bvecq_put(roll->tail);
}
