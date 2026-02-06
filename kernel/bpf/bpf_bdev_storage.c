// SPDX-License-Identifier: GPL-2.0
/*
 * BPF block device local storage
 *
 * Copyright (c) 2026 Christian Brauner (Amutable) <brauner@kernel.org>
 */

#include <linux/bpf.h>
#include <linux/bpf_local_storage.h>
#include <linux/bpf_lsm.h>
#include <linux/blkdev.h>
#include <linux/btf_ids.h>
#include <linux/fs/super.h>
#include <linux/rcupdate_trace.h>

DEFINE_BPF_STORAGE_CACHE(bdev_cache);

static DEFINE_PER_CPU(int, bpf_bdev_storage_busy);

static void bpf_bdev_storage_lock(void)
{
	cant_migrate();
	this_cpu_inc(bpf_bdev_storage_busy);
}

static void bpf_bdev_storage_unlock(void)
{
	this_cpu_dec(bpf_bdev_storage_busy);
}

static bool bpf_bdev_storage_trylock(void)
{
	cant_migrate();
	if (unlikely(this_cpu_inc_return(bpf_bdev_storage_busy) != 1)) {
		this_cpu_dec(bpf_bdev_storage_busy);
		return false;
	}
	return true;
}

DEFINE_LOCK_GUARD_0(bpf_bdev_storage, bpf_bdev_storage_lock(), bpf_bdev_storage_unlock())

static struct bpf_local_storage __rcu **bpf_bdev_storage_ptr(void *owner)
{
	struct block_device *bdev = owner;
	struct bpf_storage_blob *bsb;

	bsb = bpf_bdev(bdev);
	if (!bsb)
		return NULL;
	return &bsb->storage;
}

static struct bpf_local_storage_data *
bpf_bdev_storage_lookup(struct block_device *bdev, struct bpf_map *map,
			bool cacheit_lockit)
{
	struct bpf_local_storage *bdev_storage;
	struct bpf_local_storage_map *smap;
	struct bpf_storage_blob *bsb;

	bsb = bpf_bdev(bdev);
	if (!bsb)
		return NULL;

	bdev_storage = rcu_dereference_check(bsb->storage,
					     bpf_rcu_lock_held());
	if (!bdev_storage)
		return NULL;

	smap = (struct bpf_local_storage_map *)map;
	return bpf_local_storage_lookup(bdev_storage, smap, cacheit_lockit);
}

void bpf_bdev_storage_free(struct block_device *bdev)
{
	struct bpf_local_storage *local_storage;
	struct bpf_storage_blob *bsb;

	bsb = bpf_bdev(bdev);
	if (!bsb)
		return;

	rcu_read_lock_dont_migrate();
	local_storage = rcu_dereference(bsb->storage);
	if (local_storage) {
		guard(bpf_bdev_storage)();
		bpf_local_storage_destroy(local_storage);
	}
	rcu_read_unlock_migrate();
}

static void *bpf_fd_bdev_storage_lookup_elem(struct bpf_map *map, void *key)
{
	struct bpf_local_storage_data *sdata;
	struct block_device *bdev;
	CLASS(fd_raw, f)(*(int *)key);

	if (fd_empty(f))
		return ERR_PTR(-EBADF);
	if (!S_ISBLK(file_inode(fd_file(f))->i_mode))
		return ERR_PTR(-EBADF);
	bdev = file_bdev(fd_file(f));

	guard(bpf_bdev_storage)();
	sdata = bpf_bdev_storage_lookup(bdev, map, true);
	return sdata ? sdata->data : NULL;
}

static long bpf_fd_bdev_storage_update_elem(struct bpf_map *map, void *key,
					    void *value, u64 map_flags)
{
	struct bpf_local_storage_data *sdata;
	struct block_device *bdev;
	CLASS(fd_raw, f)(*(int *)key);

	if (fd_empty(f))
		return -EBADF;
	if (!S_ISBLK(file_inode(fd_file(f))->i_mode))
		return -EBADF;
	bdev = file_bdev(fd_file(f));
	if (!bpf_bdev_storage_ptr(bdev))
		return -EBADF;

	guard(bpf_bdev_storage)();
	sdata = bpf_local_storage_update(bdev,
				(struct bpf_local_storage_map *)map, value,
				map_flags, false, GFP_ATOMIC);
	return PTR_ERR_OR_ZERO(sdata);
}

static int bdev_storage_delete(struct block_device *bdev, struct bpf_map *map)
{
	struct bpf_local_storage_data *sdata;

	sdata = bpf_bdev_storage_lookup(bdev, map, false);
	if (!sdata)
		return -ENOENT;

	bpf_selem_unlink(SELEM(sdata), false);
	return 0;
}

static long bpf_fd_bdev_storage_delete_elem(struct bpf_map *map, void *key)
{
	struct block_device *bdev;
	CLASS(fd_raw, f)(*(int *)key);

	if (fd_empty(f))
		return -EBADF;
	if (!S_ISBLK(file_inode(fd_file(f))->i_mode))
		return -EBADF;
	bdev = file_bdev(fd_file(f));

	guard(bpf_bdev_storage)();
	return bdev_storage_delete(bdev, map);
}

static int notsupp_get_next_key(struct bpf_map *map, void *key, void *next_key)
{
	return -ENOTSUPP;
}

static struct bpf_map *bpf_bdev_storage_map_alloc(union bpf_attr *attr)
{
	return bpf_local_storage_map_alloc(attr, &bdev_cache, true);
}

static void bpf_bdev_storage_map_free(struct bpf_map *map)
{
	bpf_local_storage_map_free(map, &bdev_cache, &bpf_bdev_storage_busy);
}

__bpf_kfunc_start_defs();

/*
 * bpf_bdev_storage_get - Get or create block device local storage
 * @map__map: Pointer to BPF_MAP_TYPE_BDEV_STORAGE map
 * @bdev: Block device to get storage for
 * @flags: BPF_LOCAL_STORAGE_GET_F_CREATE to create if not exists
 *
 * Returns pointer to storage value, or NULL on failure.
 * When creating, storage is zero-initialized; write initial values
 * through the returned pointer.
 */
__bpf_kfunc void *bpf_bdev_storage_get(struct bpf_map *map__map,
					struct block_device *bdev, u64 flags)
{
	struct bpf_map *map = map__map;
	struct bpf_local_storage_data *sdata;
	bool nobusy;

	WARN_ON_ONCE(!bpf_rcu_lock_held());

	if (map->map_type != BPF_MAP_TYPE_BDEV_STORAGE)
		return NULL;
	if (flags & ~(BPF_LOCAL_STORAGE_GET_F_CREATE))
		return NULL;
	if (!bdev)
		return NULL;
	if (!bpf_bdev_storage_ptr(bdev))
		return NULL;

	nobusy = bpf_bdev_storage_trylock();
	sdata = bpf_bdev_storage_lookup(bdev, map, nobusy);
	if (sdata)
		goto unlock;

	if (!(flags & BPF_LOCAL_STORAGE_GET_F_CREATE))
		goto unlock;
	if (!nobusy)
		goto unlock;

	sdata = bpf_local_storage_update(bdev,
				(struct bpf_local_storage_map *)map,
				NULL, BPF_NOEXIST, false, GFP_ATOMIC);

unlock:
	if (nobusy)
		bpf_bdev_storage_unlock();
	if (IS_ERR_OR_NULL(sdata))
		return NULL;
	return sdata->data;
}

/*
 * bpf_bdev_storage_delete - Delete block device local storage
 * @map__map: Pointer to BPF_MAP_TYPE_BDEV_STORAGE map
 * @bdev: Block device to delete storage from
 *
 * Returns 0 on success, negative error on failure.
 */
__bpf_kfunc int bpf_bdev_storage_delete(struct bpf_map *map__map,
					 struct block_device *bdev)
{
	struct bpf_map *map = map__map;
	int ret;

	WARN_ON_ONCE(!bpf_rcu_lock_held());

	if (map->map_type != BPF_MAP_TYPE_BDEV_STORAGE)
		return -EINVAL;
	if (!bdev)
		return -EINVAL;
	if (!bpf_bdev_storage_trylock())
		return -EBUSY;
	ret = bdev_storage_delete(bdev, map);
	bpf_bdev_storage_unlock();
	return ret;
}

/*
 * bpf_get_file_bdev - Get block device from file
 * @file: File to extract block device from
 *
 * Returns pointer to block_device if the file is a block device file,
 * or NULL if it is not.
 *
 * This may be called from security_file_open() where the file's
 * f_mapping has not yet been remapped to the block device's mapping.
 * In that case f_mapping->host is the filesystem inode (e.g. devtmpfs),
 * not the bdev inode, so file_bdev() would do container_of() on the
 * wrong inode type. Guard against this by verifying that f_mapping->host
 * is actually on the blockdev superblock before calling I_BDEV().
 */
__bpf_kfunc struct block_device *bpf_get_file_bdev(struct file *file)
{
	struct inode *inode;

	if (!S_ISBLK(file_inode(file)->i_mode))
		return NULL;

	inode = file->f_mapping->host;
	if (!sb_is_blkdev_sb(inode->i_sb))
		return NULL;

	return I_BDEV(inode);
}

__bpf_kfunc_end_defs();

const struct bpf_map_ops bdev_storage_map_ops = {
	.map_meta_equal		= bpf_map_meta_equal,
	.map_alloc_check	= bpf_local_storage_map_alloc_check,
	.map_alloc		= bpf_bdev_storage_map_alloc,
	.map_free		= bpf_bdev_storage_map_free,
	.map_get_next_key	= notsupp_get_next_key,
	.map_lookup_elem	= bpf_fd_bdev_storage_lookup_elem,
	.map_update_elem	= bpf_fd_bdev_storage_update_elem,
	.map_delete_elem	= bpf_fd_bdev_storage_delete_elem,
	.map_check_btf		= bpf_local_storage_map_check_btf,
	.map_mem_usage		= bpf_local_storage_map_mem_usage,
	.map_btf_id		= &bpf_local_storage_map_btf_id[0],
	.map_owner_storage_ptr	= bpf_bdev_storage_ptr,
};

BTF_KFUNCS_START(bpf_bdev_storage_kfunc_ids)
BTF_ID_FLAGS(func, bpf_bdev_storage_get, KF_RCU | KF_RET_NULL)
BTF_ID_FLAGS(func, bpf_bdev_storage_delete, KF_RCU)
BTF_ID_FLAGS(func, bpf_get_file_bdev, KF_RCU_PROTECTED | KF_RET_NULL)
BTF_KFUNCS_END(bpf_bdev_storage_kfunc_ids)

static const struct btf_kfunc_id_set bpf_bdev_storage_kfunc_set = {
	.owner = THIS_MODULE,
	.set   = &bpf_bdev_storage_kfunc_ids,
};

static int __init bpf_bdev_storage_kfunc_init(void)
{
	return register_btf_kfunc_id_set(BPF_PROG_TYPE_LSM,
					 &bpf_bdev_storage_kfunc_set);
}
late_initcall(bpf_bdev_storage_kfunc_init);
