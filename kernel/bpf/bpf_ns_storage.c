// SPDX-License-Identifier: GPL-2.0
/*
 * BPF namespace local storage
 *
 * Copyright (c) 2026 Christian Brauner (Amutable) <brauner@kernel.org>
 */

#include <linux/bpf.h>
#include <linux/bpf_local_storage.h>
#include <linux/bpf_lsm.h>
#include <linux/btf_ids.h>
#include <linux/cgroup_namespace.h>
#include <linux/ipc_namespace.h>
#include <linux/ns_common.h>
#include <linux/nsproxy.h>
#include <linux/nstree.h>
#include <linux/pid_namespace.h>
#include <linux/time_namespace.h>
#include <linux/user_namespace.h>
#include <linux/uts_namespace.h>
#include <net/net_namespace.h>

#define BPF_LOCAL_STORAGE_CREATE_FLAG_MASK (BPF_F_NO_PREALLOC | BPF_F_CLONE)

DEFINE_BPF_STORAGE_CACHE(ns_cache);

static DEFINE_PER_CPU(int, bpf_ns_storage_busy);

static void bpf_ns_storage_lock(void)
{
	cant_migrate();
	this_cpu_inc(bpf_ns_storage_busy);
}

static void bpf_ns_storage_unlock(void)
{
	this_cpu_dec(bpf_ns_storage_busy);
}

static bool bpf_ns_storage_trylock(void)
{
	cant_migrate();
	if (unlikely(this_cpu_inc_return(bpf_ns_storage_busy) != 1)) {
		this_cpu_dec(bpf_ns_storage_busy);
		return false;
	}
	return true;
}

DEFINE_LOCK_GUARD_0(bpf_ns_storage, bpf_ns_storage_lock(), bpf_ns_storage_unlock())

static struct bpf_local_storage __rcu **bpf_ns_storage_ptr(void *owner)
{
	struct ns_common *ns = owner;
	struct bpf_storage_blob *bsb;

	bsb = bpf_ns(ns);
	if (!bsb)
		return NULL;
	return &bsb->storage;
}

static struct bpf_local_storage_data *
bpf_ns_storage_lookup(struct ns_common *ns, struct bpf_map *map,
		      bool cacheit_lockit)
{
	struct bpf_local_storage *ns_storage;
	struct bpf_local_storage_map *smap;
	struct bpf_storage_blob *bsb;

	bsb = bpf_ns(ns);
	if (!bsb)
		return NULL;

	ns_storage = rcu_dereference_check(bsb->storage, bpf_rcu_lock_held());
	if (!ns_storage)
		return NULL;

	smap = (struct bpf_local_storage_map *)map;
	return bpf_local_storage_lookup(ns_storage, smap, cacheit_lockit);
}

void bpf_ns_storage_free(struct ns_common *ns)
{
	struct bpf_local_storage *local_storage;
	struct bpf_storage_blob *bsb;

	bsb = bpf_ns(ns);
	if (!bsb)
		return;

	rcu_read_lock_dont_migrate();
	local_storage = rcu_dereference(bsb->storage);
	if (local_storage) {
		guard(bpf_ns_storage)();
		bpf_local_storage_destroy(local_storage);
	}
	rcu_read_unlock_migrate();
}

static void *bpf_ns_storage_lookup_elem(struct bpf_map *map, void *key)
{
	struct bpf_local_storage_data *sdata;
	struct ns_common *ns;
	u64 ns_id = *(u64 *)key;

	/* Called under rcu_read_lock() from bpf_map_copy_value(). */
	ns = ns_tree_lookup_rcu(ns_id, 0);
	if (!ns)
		return ERR_PTR(-ENOENT);

	guard(bpf_ns_storage)();
	sdata = bpf_ns_storage_lookup(ns, map, true);
	if (!sdata)
		return NULL;
	return sdata->data;
}

static long bpf_ns_storage_update_elem(struct bpf_map *map, void *key,
				       void *value, u64 map_flags)
{
	struct ns_common *ns;
	u64 ns_id = *(u64 *)key;

	/* Called under rcu_read_lock() from bpf_map_update_value(). */
	ns = ns_tree_lookup_rcu(ns_id, 0);
	if (!ns)
		return -ENOENT;
	if (!bpf_ns_storage_ptr(ns))
		return -ENOENT;
	guard(bpf_ns_storage)();
	return PTR_ERR_OR_ZERO(bpf_local_storage_update(ns,
				(struct bpf_local_storage_map *)map, value, map_flags,
				false, GFP_ATOMIC));
}

static int ns_storage_delete(struct ns_common *ns, struct bpf_map *map)
{
	struct bpf_local_storage_data *sdata;

	sdata = bpf_ns_storage_lookup(ns, map, false);
	if (!sdata)
		return -ENOENT;
	bpf_selem_unlink(SELEM(sdata), false);
	return 0;
}

static long bpf_ns_storage_delete_elem(struct bpf_map *map, void *key)
{
	struct ns_common *ns;
	u64 ns_id = *(u64 *)key;

	/* Called under rcu_read_lock() from the BPF syscall layer. */
	ns = ns_tree_lookup_rcu(ns_id, 0);
	if (!ns)
		return -ENOENT;
	guard(bpf_ns_storage)();
	return ns_storage_delete(ns, map);
}

static int notsupp_get_next_key(struct bpf_map *map, void *key, void *next_key)
{
	return -ENOTSUPP;
}

static int bpf_ns_storage_map_alloc_check(union bpf_attr *attr)
{
	if (attr->key_size != sizeof(__u64))
		return -EINVAL;
	if (attr->map_flags & ~BPF_LOCAL_STORAGE_CREATE_FLAG_MASK)
		return -EINVAL;
	if (!(attr->map_flags & BPF_F_NO_PREALLOC))
		return -EINVAL;
	if (attr->max_entries)
		return -EINVAL;
	if (!attr->value_size)
		return -EINVAL;
	if (!attr->btf_key_type_id)
		return -EINVAL;
	if (!attr->btf_value_type_id)
		return -EINVAL;
	if (attr->value_size > BPF_LOCAL_STORAGE_MAX_VALUE_SIZE)
		return -E2BIG;
	return 0;
}

static struct bpf_map *bpf_ns_storage_map_alloc(union bpf_attr *attr)
{
	return bpf_local_storage_map_alloc(attr, &ns_cache, true);
}

static void bpf_ns_storage_map_free(struct bpf_map *map)
{
	bpf_local_storage_map_free(map, &ns_cache, &bpf_ns_storage_busy);
}

__bpf_kfunc_start_defs();

/*
 * bpf_ns_storage_get - Get or create namespace local storage
 * @map__map: Pointer to BPF_MAP_TYPE_NS_STORAGE map
 * @ns: Namespace to get storage for
 * @flags: BPF_LOCAL_STORAGE_GET_F_CREATE to create if not exists
 *
 * Returns pointer to storage value, or NULL on failure.
 * When creating, storage is zero-initialized; write initial values
 * through the returned pointer.
 */
__bpf_kfunc void *bpf_ns_storage_get(struct bpf_map *map__map, struct ns_common *ns,
				     u64 flags)
{
	struct bpf_map *map = map__map;
	struct bpf_local_storage_data *sdata;
	bool nobusy;

	WARN_ON_ONCE(!bpf_rcu_lock_held());

	if (map->map_type != BPF_MAP_TYPE_NS_STORAGE)
		return NULL;
	if (flags & ~(BPF_LOCAL_STORAGE_GET_F_CREATE))
		return NULL;
	if (!ns)
		return NULL;
	if (!bpf_ns_storage_ptr(ns))
		return NULL;

	nobusy = bpf_ns_storage_trylock();
	sdata = bpf_ns_storage_lookup(ns, map, nobusy);
	if (sdata)
		goto unlock;
	/*
	 * If ns->ns_id isn't set we're called from the namespace
	 * allocation hook before the namespace has been added to the
	 * namespace trees. Always allow initialization in that case.
	 */
	if (ns->ns_id && !__ns_ref_active_read(ns))
		goto unlock;
	if (!(flags & BPF_LOCAL_STORAGE_GET_F_CREATE))
		goto unlock;
	if (!nobusy)
		goto unlock;

	sdata = bpf_local_storage_update(ns, (struct bpf_local_storage_map *)map,
					 NULL, BPF_NOEXIST, false, GFP_ATOMIC);

unlock:
	if (nobusy)
		bpf_ns_storage_unlock();
	if (IS_ERR_OR_NULL(sdata))
		return NULL;
	return sdata->data;
}

/*
 * bpf_ns_storage_delete - Delete namespace local storage
 * @map__map: Pointer to BPF_MAP_TYPE_NS_STORAGE map
 * @ns: Namespace to delete storage from
 *
 * Returns 0 on success, negative error on failure.
 */
__bpf_kfunc int bpf_ns_storage_delete(struct bpf_map *map__map, struct ns_common *ns)
{
	struct bpf_map *map = map__map;
	int ret;

	WARN_ON_ONCE(!bpf_rcu_lock_held());

	if (map->map_type != BPF_MAP_TYPE_NS_STORAGE)
		return -EINVAL;
	if (!ns)
		return -EINVAL;
	if (!bpf_ns_storage_trylock())
		return -EBUSY;
	ret = ns_storage_delete(ns, map);
	bpf_ns_storage_unlock();
	return ret;
}

/*
 * bpf_get_current_ns - Get the ns_common of the current task's namespace
 * @ns_type: Namespace type (CLONE_NEWUTS, CLONE_NEWIPC, etc.)
 *
 * Returns a pointer to the ns_common of the specified namespace type
 * for the current task, or NULL on failure. The returned pointer is
 * RCU-protected and valid for the duration of the RCU critical section.
 * Must be called from an RCU critical section.
 */
__bpf_kfunc struct ns_common *bpf_get_current_ns(u64 ns_type)
{
	struct nsproxy *nsproxy;

	nsproxy = current->nsproxy;
	if (!nsproxy)
		return NULL;

	switch (ns_type) {
	case CLONE_NEWUTS:
		return nsproxy->uts_ns ? &nsproxy->uts_ns->ns : NULL;
	case CLONE_NEWIPC:
		return nsproxy->ipc_ns ? &nsproxy->ipc_ns->ns : NULL;
	case CLONE_NEWPID:
		return nsproxy->pid_ns_for_children ?
			&nsproxy->pid_ns_for_children->ns : NULL;
	case CLONE_NEWNET:
		return nsproxy->net_ns ? &nsproxy->net_ns->ns : NULL;
	case CLONE_NEWCGROUP:
		return nsproxy->cgroup_ns ? &nsproxy->cgroup_ns->ns : NULL;
	case CLONE_NEWTIME:
		return nsproxy->time_ns ? &nsproxy->time_ns->ns : NULL;
	default:
		return NULL;
	}
}

__bpf_kfunc_end_defs();

static int bpf_ns_storage_map_check_btf(const struct bpf_map *map,
					const struct btf *btf,
					const struct btf_type *key_type,
					const struct btf_type *value_type)
{
	if (!btf_type_is_i64(key_type))
		return -EINVAL;
	return 0;
}

const struct bpf_map_ops ns_storage_map_ops = {
	.map_meta_equal		= bpf_map_meta_equal,
	.map_alloc_check	= bpf_ns_storage_map_alloc_check,
	.map_alloc		= bpf_ns_storage_map_alloc,
	.map_free		= bpf_ns_storage_map_free,
	.map_get_next_key	= notsupp_get_next_key,
	.map_lookup_elem	= bpf_ns_storage_lookup_elem,
	.map_update_elem	= bpf_ns_storage_update_elem,
	.map_delete_elem	= bpf_ns_storage_delete_elem,
	.map_check_btf		= bpf_ns_storage_map_check_btf,
	.map_mem_usage		= bpf_local_storage_map_mem_usage,
	.map_btf_id		= &bpf_local_storage_map_btf_id[0],
	.map_owner_storage_ptr	= bpf_ns_storage_ptr,
};

BTF_KFUNCS_START(bpf_ns_storage_kfunc_ids)
BTF_ID_FLAGS(func, bpf_ns_storage_get, KF_RCU | KF_RET_NULL)
BTF_ID_FLAGS(func, bpf_ns_storage_delete, KF_RCU)
BTF_ID_FLAGS(func, bpf_get_current_ns, KF_RCU_PROTECTED | KF_RET_NULL)
BTF_KFUNCS_END(bpf_ns_storage_kfunc_ids)

static const struct btf_kfunc_id_set bpf_ns_storage_kfunc_set = {
	.owner = THIS_MODULE,
	.set   = &bpf_ns_storage_kfunc_ids,
};

static int __init bpf_ns_storage_kfunc_init(void)
{
	return register_btf_kfunc_id_set(BPF_PROG_TYPE_LSM, &bpf_ns_storage_kfunc_set);
}
late_initcall(bpf_ns_storage_kfunc_init);
