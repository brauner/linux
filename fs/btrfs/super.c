// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2007 Oracle.  All rights reserved.
 */

#include <linux/blkdev.h>
#include <linux/module.h>
#include <linux/fs.h>
#include <linux/pagemap.h>
#include <linux/highmem.h>
#include <linux/time.h>
#include <linux/init.h>
#include <linux/seq_file.h>
#include <linux/string.h>
#include <linux/backing-dev.h>
#include <linux/mount.h>
#include <linux/writeback.h>
#include <linux/statfs.h>
#include <linux/compat.h>
#include <linux/parser.h>
#include <linux/ctype.h>
#include <linux/namei.h>
#include <linux/miscdevice.h>
#include <linux/magic.h>
#include <linux/slab.h>
#include <linux/ratelimit.h>
#include <linux/crc32c.h>
#include <linux/btrfs.h>
#include "messages.h"
#include "delayed-inode.h"
#include "ctree.h"
#include "disk-io.h"
#include "transaction.h"
#include "btrfs_inode.h"
#include "print-tree.h"
#include "props.h"
#include "xattr.h"
#include "bio.h"
#include "export.h"
#include "compression.h"
#include "rcu-string.h"
#include "dev-replace.h"
#include "free-space-cache.h"
#include "backref.h"
#include "space-info.h"
#include "sysfs.h"
#include "zoned.h"
#include "tests/btrfs-tests.h"
#include "block-group.h"
#include "discard.h"
#include "qgroup.h"
#include "raid56.h"
#include "fs.h"
#include "accessors.h"
#include "defrag.h"
#include "dir-item.h"
#include "ioctl.h"
#include "scrub.h"
#include "verity.h"
#include "super.h"
#include "extent-tree.h"
#include "params.h"
#define CREATE_TRACE_POINTS
#include <trace/events/btrfs.h>

static const struct super_operations btrfs_super_ops;

static void btrfs_put_super(struct super_block *sb)
{
	close_ctree(btrfs_sb(sb));
}

char *btrfs_get_subvol_name_from_objectid(struct btrfs_fs_info *fs_info,
					  u64 subvol_objectid)
{
	struct btrfs_root *root = fs_info->tree_root;
	struct btrfs_root *fs_root = NULL;
	struct btrfs_root_ref *root_ref;
	struct btrfs_inode_ref *inode_ref;
	struct btrfs_key key;
	struct btrfs_path *path = NULL;
	char *name = NULL, *ptr;
	u64 dirid;
	int len;
	int ret;

	path = btrfs_alloc_path();
	if (!path) {
		ret = -ENOMEM;
		goto err;
	}

	name = kmalloc(PATH_MAX, GFP_KERNEL);
	if (!name) {
		ret = -ENOMEM;
		goto err;
	}
	ptr = name + PATH_MAX - 1;
	ptr[0] = '\0';

	/*
	 * Walk up the subvolume trees in the tree of tree roots by root
	 * backrefs until we hit the top-level subvolume.
	 */
	while (subvol_objectid != BTRFS_FS_TREE_OBJECTID) {
		key.objectid = subvol_objectid;
		key.type = BTRFS_ROOT_BACKREF_KEY;
		key.offset = (u64)-1;

		ret = btrfs_search_backwards(root, &key, path);
		if (ret < 0) {
			goto err;
		} else if (ret > 0) {
			ret = -ENOENT;
			goto err;
		}

		subvol_objectid = key.offset;

		root_ref = btrfs_item_ptr(path->nodes[0], path->slots[0],
					  struct btrfs_root_ref);
		len = btrfs_root_ref_name_len(path->nodes[0], root_ref);
		ptr -= len + 1;
		if (ptr < name) {
			ret = -ENAMETOOLONG;
			goto err;
		}
		read_extent_buffer(path->nodes[0], ptr + 1,
				   (unsigned long)(root_ref + 1), len);
		ptr[0] = '/';
		dirid = btrfs_root_ref_dirid(path->nodes[0], root_ref);
		btrfs_release_path(path);

		fs_root = btrfs_get_fs_root(fs_info, subvol_objectid, true);
		if (IS_ERR(fs_root)) {
			ret = PTR_ERR(fs_root);
			fs_root = NULL;
			goto err;
		}

		/*
		 * Walk up the filesystem tree by inode refs until we hit the
		 * root directory.
		 */
		while (dirid != BTRFS_FIRST_FREE_OBJECTID) {
			key.objectid = dirid;
			key.type = BTRFS_INODE_REF_KEY;
			key.offset = (u64)-1;

			ret = btrfs_search_backwards(fs_root, &key, path);
			if (ret < 0) {
				goto err;
			} else if (ret > 0) {
				ret = -ENOENT;
				goto err;
			}

			dirid = key.offset;

			inode_ref = btrfs_item_ptr(path->nodes[0],
						   path->slots[0],
						   struct btrfs_inode_ref);
			len = btrfs_inode_ref_name_len(path->nodes[0],
						       inode_ref);
			ptr -= len + 1;
			if (ptr < name) {
				ret = -ENAMETOOLONG;
				goto err;
			}
			read_extent_buffer(path->nodes[0], ptr + 1,
					   (unsigned long)(inode_ref + 1), len);
			ptr[0] = '/';
			btrfs_release_path(path);
		}
		btrfs_put_root(fs_root);
		fs_root = NULL;
	}

	btrfs_free_path(path);
	if (ptr == name + PATH_MAX - 1) {
		name[0] = '/';
		name[1] = '\0';
	} else {
		memmove(name, ptr, name + PATH_MAX - ptr);
	}
	return name;

err:
	btrfs_put_root(fs_root);
	btrfs_free_path(path);
	kfree(name);
	return ERR_PTR(ret);
}

int btrfs_fill_super(struct fs_context *fc, struct super_block *sb,
		     struct btrfs_fs_devices *fs_devices)
{
	struct inode *inode;
	struct btrfs_fs_info *fs_info = btrfs_sb(sb);
	int err;

	sb->s_maxbytes = MAX_LFS_FILESIZE;
	sb->s_magic = BTRFS_SUPER_MAGIC;
	sb->s_op = &btrfs_super_ops;
	sb->s_d_op = &btrfs_dentry_operations;
	sb->s_export_op = &btrfs_export_ops;
#ifdef CONFIG_FS_VERITY
	sb->s_vop = &btrfs_verityops;
#endif
	sb->s_xattr = btrfs_xattr_handlers;
	sb->s_time_gran = 1;
	sb->s_iflags |= SB_I_CGROUPWB;

	err = super_setup_bdi(sb);
	if (err) {
		btrfs_err(fs_info, "super_setup_bdi failed");
		return err;
	}

	err = open_ctree(fc, sb, fs_devices);
	if (err) {
		btrfs_err(fs_info, "open_ctree failed");
		return err;
	}

	inode = btrfs_iget(sb, BTRFS_FIRST_FREE_OBJECTID, fs_info->fs_root);
	if (IS_ERR(inode)) {
		err = PTR_ERR(inode);
		btrfs_handle_fs_error(fs_info, err, NULL);
		goto fail_close;
	}

	sb->s_root = d_make_root(inode);
	if (!sb->s_root) {
		err = -ENOMEM;
		goto fail_close;
	}

	sb->s_flags |= SB_ACTIVE;
	return 0;

fail_close:
	close_ctree(fs_info);
	return err;
}

int btrfs_sync_fs(struct super_block *sb, int wait)
{
	struct btrfs_trans_handle *trans;
	struct btrfs_fs_info *fs_info = btrfs_sb(sb);
	struct btrfs_root *root = fs_info->tree_root;

	trace_btrfs_sync_fs(fs_info, wait);

	if (!wait) {
		filemap_flush(fs_info->btree_inode->i_mapping);
		return 0;
	}

	btrfs_wait_ordered_roots(fs_info, U64_MAX, 0, (u64)-1);

	trans = btrfs_attach_transaction_barrier(root);
	if (IS_ERR(trans)) {
		/* no transaction, don't bother */
		if (PTR_ERR(trans) == -ENOENT) {
			/*
			 * Exit unless we have some pending changes
			 * that need to go through commit
			 */
			if (!test_bit(BTRFS_FS_NEED_TRANS_COMMIT,
				      &fs_info->flags))
				return 0;
			/*
			 * A non-blocking test if the fs is frozen. We must not
			 * start a new transaction here otherwise a deadlock
			 * happens. The pending operations are delayed to the
			 * next commit after thawing.
			 */
			if (sb_start_write_trylock(sb))
				sb_end_write(sb);
			else
				return 0;
			trans = btrfs_start_transaction(root, 0);
		}
		if (IS_ERR(trans))
			return PTR_ERR(trans);
	}
	return btrfs_commit_transaction(trans);
}

static void print_rescue_option(struct seq_file *seq, const char *s, bool *printed)
{
	seq_printf(seq, "%s%s", (*printed) ? ":" : ",rescue=", s);
	*printed = true;
}

static int btrfs_show_options(struct seq_file *seq, struct dentry *dentry)
{
	struct btrfs_fs_info *info = btrfs_sb(dentry->d_sb);
	const char *compress_type;
	const char *subvol_name;
	bool printed = false;

	if (btrfs_test_opt(info, DEGRADED))
		seq_puts(seq, ",degraded");
	if (btrfs_test_opt(info, NODATASUM))
		seq_puts(seq, ",nodatasum");
	if (btrfs_test_opt(info, NODATACOW))
		seq_puts(seq, ",nodatacow");
	if (btrfs_test_opt(info, NOBARRIER))
		seq_puts(seq, ",nobarrier");
	if (info->max_inline != BTRFS_DEFAULT_MAX_INLINE)
		seq_printf(seq, ",max_inline=%llu", info->max_inline);
	if (info->thread_pool_size !=  min_t(unsigned long,
					     num_online_cpus() + 2, 8))
		seq_printf(seq, ",thread_pool=%u", info->thread_pool_size);
	if (btrfs_test_opt(info, COMPRESS)) {
		compress_type = btrfs_compress_type2str(info->compress_type);
		if (btrfs_test_opt(info, FORCE_COMPRESS))
			seq_printf(seq, ",compress-force=%s", compress_type);
		else
			seq_printf(seq, ",compress=%s", compress_type);
		if (info->compress_level)
			seq_printf(seq, ":%d", info->compress_level);
	}
	if (btrfs_test_opt(info, NOSSD))
		seq_puts(seq, ",nossd");
	if (btrfs_test_opt(info, SSD_SPREAD))
		seq_puts(seq, ",ssd_spread");
	else if (btrfs_test_opt(info, SSD))
		seq_puts(seq, ",ssd");
	if (btrfs_test_opt(info, NOTREELOG))
		seq_puts(seq, ",notreelog");
	if (btrfs_test_opt(info, NOLOGREPLAY))
		print_rescue_option(seq, "nologreplay", &printed);
	if (btrfs_test_opt(info, USEBACKUPROOT))
		print_rescue_option(seq, "usebackuproot", &printed);
	if (btrfs_test_opt(info, IGNOREBADROOTS))
		print_rescue_option(seq, "ignorebadroots", &printed);
	if (btrfs_test_opt(info, IGNOREDATACSUMS))
		print_rescue_option(seq, "ignoredatacsums", &printed);
	if (btrfs_test_opt(info, FLUSHONCOMMIT))
		seq_puts(seq, ",flushoncommit");
	if (btrfs_test_opt(info, DISCARD_SYNC))
		seq_puts(seq, ",discard");
	if (btrfs_test_opt(info, DISCARD_ASYNC))
		seq_puts(seq, ",discard=async");
	if (!(info->sb->s_flags & SB_POSIXACL))
		seq_puts(seq, ",noacl");
	if (btrfs_free_space_cache_v1_active(info))
		seq_puts(seq, ",space_cache");
	else if (btrfs_fs_compat_ro(info, FREE_SPACE_TREE))
		seq_puts(seq, ",space_cache=v2");
	else
		seq_puts(seq, ",nospace_cache");
	if (btrfs_test_opt(info, RESCAN_UUID_TREE))
		seq_puts(seq, ",rescan_uuid_tree");
	if (btrfs_test_opt(info, CLEAR_CACHE))
		seq_puts(seq, ",clear_cache");
	if (btrfs_test_opt(info, USER_SUBVOL_RM_ALLOWED))
		seq_puts(seq, ",user_subvol_rm_allowed");
	if (btrfs_test_opt(info, ENOSPC_DEBUG))
		seq_puts(seq, ",enospc_debug");
	if (btrfs_test_opt(info, AUTO_DEFRAG))
		seq_puts(seq, ",autodefrag");
	if (btrfs_test_opt(info, SKIP_BALANCE))
		seq_puts(seq, ",skip_balance");
#ifdef CONFIG_BTRFS_FS_CHECK_INTEGRITY
	if (btrfs_test_opt(info, CHECK_INTEGRITY_DATA))
		seq_puts(seq, ",check_int_data");
	else if (btrfs_test_opt(info, CHECK_INTEGRITY))
		seq_puts(seq, ",check_int");
	if (info->check_integrity_print_mask)
		seq_printf(seq, ",check_int_print_mask=%d",
				info->check_integrity_print_mask);
#endif
	if (info->metadata_ratio)
		seq_printf(seq, ",metadata_ratio=%u", info->metadata_ratio);
	if (btrfs_test_opt(info, PANIC_ON_FATAL_ERROR))
		seq_puts(seq, ",fatal_errors=panic");
	if (info->commit_interval != BTRFS_DEFAULT_COMMIT_INTERVAL)
		seq_printf(seq, ",commit=%u", info->commit_interval);
#ifdef CONFIG_BTRFS_DEBUG
	if (btrfs_test_opt(info, FRAGMENT_DATA))
		seq_puts(seq, ",fragment=data");
	if (btrfs_test_opt(info, FRAGMENT_METADATA))
		seq_puts(seq, ",fragment=metadata");
#endif
	if (btrfs_test_opt(info, REF_VERIFY))
		seq_puts(seq, ",ref_verify");
	seq_printf(seq, ",subvolid=%llu",
		  BTRFS_I(d_inode(dentry))->root->root_key.objectid);
	subvol_name = btrfs_get_subvol_name_from_objectid(info,
			BTRFS_I(d_inode(dentry))->root->root_key.objectid);
	if (!IS_ERR(subvol_name)) {
		seq_puts(seq, ",subvol=");
		seq_escape(seq, subvol_name, " \t\n\\");
		kfree(subvol_name);
	}
	return 0;
}

/* Used to sort the devices by max_avail(descending sort) */
static int btrfs_cmp_device_free_bytes(const void *a, const void *b)
{
	const struct btrfs_device_info *dev_info1 = a;
	const struct btrfs_device_info *dev_info2 = b;

	if (dev_info1->max_avail > dev_info2->max_avail)
		return -1;
	else if (dev_info1->max_avail < dev_info2->max_avail)
		return 1;
	return 0;
}

/*
 * sort the devices by max_avail, in which max free extent size of each device
 * is stored.(Descending Sort)
 */
static inline void btrfs_descending_sort_devices(
					struct btrfs_device_info *devices,
					size_t nr_devices)
{
	sort(devices, nr_devices, sizeof(struct btrfs_device_info),
	     btrfs_cmp_device_free_bytes, NULL);
}

/*
 * The helper to calc the free space on the devices that can be used to store
 * file data.
 */
static inline int btrfs_calc_avail_data_space(struct btrfs_fs_info *fs_info,
					      u64 *free_bytes)
{
	struct btrfs_device_info *devices_info;
	struct btrfs_fs_devices *fs_devices = fs_info->fs_devices;
	struct btrfs_device *device;
	u64 type;
	u64 avail_space;
	u64 min_stripe_size;
	int num_stripes = 1;
	int i = 0, nr_devices;
	const struct btrfs_raid_attr *rattr;

	/*
	 * We aren't under the device list lock, so this is racy-ish, but good
	 * enough for our purposes.
	 */
	nr_devices = fs_info->fs_devices->open_devices;
	if (!nr_devices) {
		smp_mb();
		nr_devices = fs_info->fs_devices->open_devices;
		ASSERT(nr_devices);
		if (!nr_devices) {
			*free_bytes = 0;
			return 0;
		}
	}

	devices_info = kmalloc_array(nr_devices, sizeof(*devices_info),
			       GFP_KERNEL);
	if (!devices_info)
		return -ENOMEM;

	/* calc min stripe number for data space allocation */
	type = btrfs_data_alloc_profile(fs_info);
	rattr = &btrfs_raid_array[btrfs_bg_flags_to_raid_index(type)];

	if (type & BTRFS_BLOCK_GROUP_RAID0)
		num_stripes = nr_devices;
	else if (type & BTRFS_BLOCK_GROUP_RAID1_MASK)
		num_stripes = rattr->ncopies;
	else if (type & BTRFS_BLOCK_GROUP_RAID10)
		num_stripes = 4;

	/* Adjust for more than 1 stripe per device */
	min_stripe_size = rattr->dev_stripes * BTRFS_STRIPE_LEN;

	rcu_read_lock();
	list_for_each_entry_rcu(device, &fs_devices->devices, dev_list) {
		if (!test_bit(BTRFS_DEV_STATE_IN_FS_METADATA,
						&device->dev_state) ||
		    !device->bdev ||
		    test_bit(BTRFS_DEV_STATE_REPLACE_TGT, &device->dev_state))
			continue;

		if (i >= nr_devices)
			break;

		avail_space = device->total_bytes - device->bytes_used;

		/* align with stripe_len */
		avail_space = rounddown(avail_space, BTRFS_STRIPE_LEN);

		/*
		 * Ensure we have at least min_stripe_size on top of the
		 * reserved space on the device.
		 */
		if (avail_space <= BTRFS_DEVICE_RANGE_RESERVED + min_stripe_size)
			continue;

		avail_space -= BTRFS_DEVICE_RANGE_RESERVED;

		devices_info[i].dev = device;
		devices_info[i].max_avail = avail_space;

		i++;
	}
	rcu_read_unlock();

	nr_devices = i;

	btrfs_descending_sort_devices(devices_info, nr_devices);

	i = nr_devices - 1;
	avail_space = 0;
	while (nr_devices >= rattr->devs_min) {
		num_stripes = min(num_stripes, nr_devices);

		if (devices_info[i].max_avail >= min_stripe_size) {
			int j;
			u64 alloc_size;

			avail_space += devices_info[i].max_avail * num_stripes;
			alloc_size = devices_info[i].max_avail;
			for (j = i + 1 - num_stripes; j <= i; j++)
				devices_info[j].max_avail -= alloc_size;
		}
		i--;
		nr_devices--;
	}

	kfree(devices_info);
	*free_bytes = avail_space;
	return 0;
}

/*
 * Calculate numbers for 'df', pessimistic in case of mixed raid profiles.
 *
 * If there's a redundant raid level at DATA block groups, use the respective
 * multiplier to scale the sizes.
 *
 * Unused device space usage is based on simulating the chunk allocator
 * algorithm that respects the device sizes and order of allocations.  This is
 * a close approximation of the actual use but there are other factors that may
 * change the result (like a new metadata chunk).
 *
 * If metadata is exhausted, f_bavail will be 0.
 */
static int btrfs_statfs(struct dentry *dentry, struct kstatfs *buf)
{
	struct btrfs_fs_info *fs_info = btrfs_sb(dentry->d_sb);
	struct btrfs_super_block *disk_super = fs_info->super_copy;
	struct btrfs_space_info *found;
	u64 total_used = 0;
	u64 total_free_data = 0;
	u64 total_free_meta = 0;
	u32 bits = fs_info->sectorsize_bits;
	__be32 *fsid = (__be32 *)fs_info->fs_devices->fsid;
	unsigned factor = 1;
	struct btrfs_block_rsv *block_rsv = &fs_info->global_block_rsv;
	int ret;
	u64 thresh = 0;
	int mixed = 0;

	list_for_each_entry(found, &fs_info->space_info, list) {
		if (found->flags & BTRFS_BLOCK_GROUP_DATA) {
			int i;

			total_free_data += found->disk_total - found->disk_used;
			total_free_data -=
				btrfs_account_ro_block_groups_free_space(found);

			for (i = 0; i < BTRFS_NR_RAID_TYPES; i++) {
				if (!list_empty(&found->block_groups[i]))
					factor = btrfs_bg_type_to_factor(
						btrfs_raid_array[i].bg_flag);
			}
		}

		/*
		 * Metadata in mixed block group profiles are accounted in data
		 */
		if (!mixed && found->flags & BTRFS_BLOCK_GROUP_METADATA) {
			if (found->flags & BTRFS_BLOCK_GROUP_DATA)
				mixed = 1;
			else
				total_free_meta += found->disk_total -
					found->disk_used;
		}

		total_used += found->disk_used;
	}

	buf->f_blocks = div_u64(btrfs_super_total_bytes(disk_super), factor);
	buf->f_blocks >>= bits;
	buf->f_bfree = buf->f_blocks - (div_u64(total_used, factor) >> bits);

	/* Account global block reserve as used, it's in logical size already */
	spin_lock(&block_rsv->lock);
	/* Mixed block groups accounting is not byte-accurate, avoid overflow */
	if (buf->f_bfree >= block_rsv->size >> bits)
		buf->f_bfree -= block_rsv->size >> bits;
	else
		buf->f_bfree = 0;
	spin_unlock(&block_rsv->lock);

	buf->f_bavail = div_u64(total_free_data, factor);
	ret = btrfs_calc_avail_data_space(fs_info, &total_free_data);
	if (ret)
		return ret;
	buf->f_bavail += div_u64(total_free_data, factor);
	buf->f_bavail = buf->f_bavail >> bits;

	/*
	 * We calculate the remaining metadata space minus global reserve. If
	 * this is (supposedly) smaller than zero, there's no space. But this
	 * does not hold in practice, the exhausted state happens where's still
	 * some positive delta. So we apply some guesswork and compare the
	 * delta to a 4M threshold.  (Practically observed delta was ~2M.)
	 *
	 * We probably cannot calculate the exact threshold value because this
	 * depends on the internal reservations requested by various
	 * operations, so some operations that consume a few metadata will
	 * succeed even if the Avail is zero. But this is better than the other
	 * way around.
	 */
	thresh = SZ_4M;

	/*
	 * We only want to claim there's no available space if we can no longer
	 * allocate chunks for our metadata profile and our global reserve will
	 * not fit in the free metadata space.  If we aren't ->full then we
	 * still can allocate chunks and thus are fine using the currently
	 * calculated f_bavail.
	 */
	if (!mixed && block_rsv->space_info->full &&
	    total_free_meta - thresh < block_rsv->size)
		buf->f_bavail = 0;

	buf->f_type = BTRFS_SUPER_MAGIC;
	buf->f_bsize = dentry->d_sb->s_blocksize;
	buf->f_namelen = BTRFS_NAME_LEN;

	/* We treat it as constant endianness (it doesn't matter _which_)
	   because we want the fsid to come out the same whether mounted
	   on a big-endian or little-endian host */
	buf->f_fsid.val[0] = be32_to_cpu(fsid[0]) ^ be32_to_cpu(fsid[2]);
	buf->f_fsid.val[1] = be32_to_cpu(fsid[1]) ^ be32_to_cpu(fsid[3]);
	/* Mask in the root object ID too, to disambiguate subvols */
	buf->f_fsid.val[0] ^=
		BTRFS_I(d_inode(dentry))->root->root_key.objectid >> 32;
	buf->f_fsid.val[1] ^=
		BTRFS_I(d_inode(dentry))->root->root_key.objectid;

	return 0;
}

static void btrfs_kill_super(struct super_block *sb)
{
	struct btrfs_fs_info *fs_info = btrfs_sb(sb);
	kill_anon_super(sb);
	btrfs_free_fs_info(fs_info);
}

struct file_system_type btrfs_fs_type = {
	.owner			= THIS_MODULE,
	.name			= "btrfs",
	.init_fs_context	= btrfs_init_fs_context,
	.parameters		= btrfs_parameter_spec,
	.kill_sb		= btrfs_kill_super,
	.fs_flags		= FS_REQUIRES_DEV | FS_BINARY_MOUNTDATA | FS_ALLOW_IDMAP,
};

MODULE_ALIAS_FS("btrfs");

static int btrfs_control_open(struct inode *inode, struct file *file)
{
	/*
	 * The control file's private_data is used to hold the
	 * transaction when it is started and is used to keep
	 * track of whether a transaction is already in progress.
	 */
	file->private_data = NULL;
	return 0;
}

/*
 * Used by /dev/btrfs-control for devices ioctls.
 */
static long btrfs_control_ioctl(struct file *file, unsigned int cmd,
				unsigned long arg)
{
	struct btrfs_ioctl_vol_args *vol;
	struct btrfs_device *device = NULL;
	dev_t devt = 0;
	int ret = -ENOTTY;

	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;

	vol = memdup_user((void __user *)arg, sizeof(*vol));
	if (IS_ERR(vol))
		return PTR_ERR(vol);
	vol->name[BTRFS_PATH_NAME_MAX] = '\0';

	switch (cmd) {
	case BTRFS_IOC_SCAN_DEV:
		mutex_lock(&uuid_mutex);
		device = btrfs_scan_one_device(vol->name, BLK_OPEN_READ);
		ret = PTR_ERR_OR_ZERO(device);
		mutex_unlock(&uuid_mutex);
		break;
	case BTRFS_IOC_FORGET_DEV:
		if (vol->name[0] != 0) {
			ret = lookup_bdev(vol->name, &devt);
			if (ret)
				break;
		}
		ret = btrfs_forget_devices(devt);
		break;
	case BTRFS_IOC_DEVICES_READY:
		mutex_lock(&uuid_mutex);
		device = btrfs_scan_one_device(vol->name, BLK_OPEN_READ);
		if (IS_ERR(device)) {
			mutex_unlock(&uuid_mutex);
			ret = PTR_ERR(device);
			break;
		}
		ret = !(device->fs_devices->num_devices ==
			device->fs_devices->total_devices);
		mutex_unlock(&uuid_mutex);
		break;
	case BTRFS_IOC_GET_SUPPORTED_FEATURES:
		ret = btrfs_ioctl_get_supported_features((void __user*)arg);
		break;
	}

	kfree(vol);
	return ret;
}

static int btrfs_freeze(struct super_block *sb)
{
	struct btrfs_trans_handle *trans;
	struct btrfs_fs_info *fs_info = btrfs_sb(sb);
	struct btrfs_root *root = fs_info->tree_root;

	set_bit(BTRFS_FS_FROZEN, &fs_info->flags);
	/*
	 * We don't need a barrier here, we'll wait for any transaction that
	 * could be in progress on other threads (and do delayed iputs that
	 * we want to avoid on a frozen filesystem), or do the commit
	 * ourselves.
	 */
	trans = btrfs_attach_transaction_barrier(root);
	if (IS_ERR(trans)) {
		/* no transaction, don't bother */
		if (PTR_ERR(trans) == -ENOENT)
			return 0;
		return PTR_ERR(trans);
	}
	return btrfs_commit_transaction(trans);
}

static int check_dev_super(struct btrfs_device *dev)
{
	struct btrfs_fs_info *fs_info = dev->fs_info;
	struct btrfs_super_block *sb;
	u16 csum_type;
	int ret = 0;

	/* This should be called with fs still frozen. */
	ASSERT(test_bit(BTRFS_FS_FROZEN, &fs_info->flags));

	/* Missing dev, no need to check. */
	if (!dev->bdev)
		return 0;

	/* Only need to check the primary super block. */
	sb = btrfs_read_dev_one_super(dev->bdev, 0, true);
	if (IS_ERR(sb))
		return PTR_ERR(sb);

	/* Verify the checksum. */
	csum_type = btrfs_super_csum_type(sb);
	if (csum_type != btrfs_super_csum_type(fs_info->super_copy)) {
		btrfs_err(fs_info, "csum type changed, has %u expect %u",
			  csum_type, btrfs_super_csum_type(fs_info->super_copy));
		ret = -EUCLEAN;
		goto out;
	}

	if (btrfs_check_super_csum(fs_info, sb)) {
		btrfs_err(fs_info, "csum for on-disk super block no longer matches");
		ret = -EUCLEAN;
		goto out;
	}

	/* Btrfs_validate_super() includes fsid check against super->fsid. */
	ret = btrfs_validate_super(fs_info, sb, 0);
	if (ret < 0)
		goto out;

	if (btrfs_super_generation(sb) != fs_info->last_trans_committed) {
		btrfs_err(fs_info, "transid mismatch, has %llu expect %llu",
			btrfs_super_generation(sb),
			fs_info->last_trans_committed);
		ret = -EUCLEAN;
		goto out;
	}
out:
	btrfs_release_disk_super(sb);
	return ret;
}

static int btrfs_unfreeze(struct super_block *sb)
{
	struct btrfs_fs_info *fs_info = btrfs_sb(sb);
	struct btrfs_device *device;
	int ret = 0;

	/*
	 * Make sure the fs is not changed by accident (like hibernation then
	 * modified by other OS).
	 * If we found anything wrong, we mark the fs error immediately.
	 *
	 * And since the fs is frozen, no one can modify the fs yet, thus
	 * we don't need to hold device_list_mutex.
	 */
	list_for_each_entry(device, &fs_info->fs_devices->devices, dev_list) {
		ret = check_dev_super(device);
		if (ret < 0) {
			btrfs_handle_fs_error(fs_info, ret,
				"super block on devid %llu got modified unexpectedly",
				device->devid);
			break;
		}
	}
	clear_bit(BTRFS_FS_FROZEN, &fs_info->flags);

	/*
	 * We still return 0, to allow VFS layer to unfreeze the fs even the
	 * above checks failed. Since the fs is either fine or read-only, we're
	 * safe to continue, without causing further damage.
	 */
	return 0;
}

static int btrfs_show_devname(struct seq_file *m, struct dentry *root)
{
	struct btrfs_fs_info *fs_info = btrfs_sb(root->d_sb);

	/*
	 * There should be always a valid pointer in latest_dev, it may be stale
	 * for a short moment in case it's being deleted but still valid until
	 * the end of RCU grace period.
	 */
	rcu_read_lock();
	seq_escape(m, btrfs_dev_name(fs_info->fs_devices->latest_dev), " \t\n\\");
	rcu_read_unlock();

	return 0;
}

static const struct super_operations btrfs_super_ops = {
	.drop_inode	= btrfs_drop_inode,
	.evict_inode	= btrfs_evict_inode,
	.put_super	= btrfs_put_super,
	.sync_fs	= btrfs_sync_fs,
	.show_options	= btrfs_show_options,
	.show_devname	= btrfs_show_devname,
	.alloc_inode	= btrfs_alloc_inode,
	.destroy_inode	= btrfs_destroy_inode,
	.free_inode	= btrfs_free_inode,
	.statfs		= btrfs_statfs,
	.freeze_fs	= btrfs_freeze,
	.unfreeze_fs	= btrfs_unfreeze,
};

static const struct file_operations btrfs_ctl_fops = {
	.open = btrfs_control_open,
	.unlocked_ioctl	 = btrfs_control_ioctl,
	.compat_ioctl = compat_ptr_ioctl,
	.owner	 = THIS_MODULE,
	.llseek = noop_llseek,
};

static struct miscdevice btrfs_misc = {
	.minor		= BTRFS_MINOR,
	.name		= "btrfs-control",
	.fops		= &btrfs_ctl_fops
};

MODULE_ALIAS_MISCDEV(BTRFS_MINOR);
MODULE_ALIAS("devname:btrfs-control");

static int __init btrfs_interface_init(void)
{
	return misc_register(&btrfs_misc);
}

static __cold void btrfs_interface_exit(void)
{
	misc_deregister(&btrfs_misc);
}

static int __init btrfs_print_mod_info(void)
{
	static const char options[] = ""
#ifdef CONFIG_BTRFS_DEBUG
			", debug=on"
#endif
#ifdef CONFIG_BTRFS_ASSERT
			", assert=on"
#endif
#ifdef CONFIG_BTRFS_FS_CHECK_INTEGRITY
			", integrity-checker=on"
#endif
#ifdef CONFIG_BTRFS_FS_REF_VERIFY
			", ref-verify=on"
#endif
#ifdef CONFIG_BLK_DEV_ZONED
			", zoned=yes"
#else
			", zoned=no"
#endif
#ifdef CONFIG_FS_VERITY
			", fsverity=yes"
#else
			", fsverity=no"
#endif
			;
	pr_info("Btrfs loaded%s\n", options);
	return 0;
}

static int register_btrfs(void)
{
	return register_filesystem(&btrfs_fs_type);
}

static void unregister_btrfs(void)
{
	unregister_filesystem(&btrfs_fs_type);
}

/* Helper structure for long init/exit functions. */
struct init_sequence {
	int (*init_func)(void);
	/* Can be NULL if the init_func doesn't need cleanup. */
	void (*exit_func)(void);
};

static const struct init_sequence mod_init_seq[] = {
	{
		.init_func = btrfs_props_init,
		.exit_func = NULL,
	}, {
		.init_func = btrfs_init_sysfs,
		.exit_func = btrfs_exit_sysfs,
	}, {
		.init_func = btrfs_init_compress,
		.exit_func = btrfs_exit_compress,
	}, {
		.init_func = btrfs_init_cachep,
		.exit_func = btrfs_destroy_cachep,
	}, {
		.init_func = btrfs_transaction_init,
		.exit_func = btrfs_transaction_exit,
	}, {
		.init_func = btrfs_ctree_init,
		.exit_func = btrfs_ctree_exit,
	}, {
		.init_func = btrfs_free_space_init,
		.exit_func = btrfs_free_space_exit,
	}, {
		.init_func = extent_state_init_cachep,
		.exit_func = extent_state_free_cachep,
	}, {
		.init_func = extent_buffer_init_cachep,
		.exit_func = extent_buffer_free_cachep,
	}, {
		.init_func = btrfs_bioset_init,
		.exit_func = btrfs_bioset_exit,
	}, {
		.init_func = extent_map_init,
		.exit_func = extent_map_exit,
	}, {
		.init_func = ordered_data_init,
		.exit_func = ordered_data_exit,
	}, {
		.init_func = btrfs_delayed_inode_init,
		.exit_func = btrfs_delayed_inode_exit,
	}, {
		.init_func = btrfs_auto_defrag_init,
		.exit_func = btrfs_auto_defrag_exit,
	}, {
		.init_func = btrfs_delayed_ref_init,
		.exit_func = btrfs_delayed_ref_exit,
	}, {
		.init_func = btrfs_prelim_ref_init,
		.exit_func = btrfs_prelim_ref_exit,
	}, {
		.init_func = btrfs_interface_init,
		.exit_func = btrfs_interface_exit,
	}, {
		.init_func = btrfs_print_mod_info,
		.exit_func = NULL,
	}, {
		.init_func = btrfs_run_sanity_tests,
		.exit_func = NULL,
	}, {
		.init_func = register_btrfs,
		.exit_func = unregister_btrfs,
	}
};

static bool mod_init_result[ARRAY_SIZE(mod_init_seq)];

static __always_inline void btrfs_exit_btrfs_fs(void)
{
	int i;

	for (i = ARRAY_SIZE(mod_init_seq) - 1; i >= 0; i--) {
		if (!mod_init_result[i])
			continue;
		if (mod_init_seq[i].exit_func)
			mod_init_seq[i].exit_func();
		mod_init_result[i] = false;
	}
}

static void __exit exit_btrfs_fs(void)
{
	btrfs_exit_btrfs_fs();
	btrfs_cleanup_fs_uuids();
}

static int __init init_btrfs_fs(void)
{
	int ret;
	int i;

	for (i = 0; i < ARRAY_SIZE(mod_init_seq); i++) {
		ASSERT(!mod_init_result[i]);
		ret = mod_init_seq[i].init_func();
		if (ret < 0) {
			btrfs_exit_btrfs_fs();
			return ret;
		}
		mod_init_result[i] = true;
	}
	return 0;
}

late_initcall(init_btrfs_fs);
module_exit(exit_btrfs_fs)

MODULE_LICENSE("GPL");
MODULE_SOFTDEP("pre: crc32c");
MODULE_SOFTDEP("pre: xxhash64");
MODULE_SOFTDEP("pre: sha256");
MODULE_SOFTDEP("pre: blake2b-256");
