.. SPDX-License-Identifier: GPL-2.0

============================
Mount references and cleanup
============================

This describes which references a mount holds and is held by, what the
private nullfs instance stands in for, and the order in which an
unmounted tree is taken down.  The code is in fs/namespace.c.

Reference count rules
=====================

A mount is allocated with one reference, its own.  That reference is
what keeps a mounted mount alive: it is held for as long as the mount is
mounted and is only ever dropped by the cleanup of an unmount.  Nothing
else in the tree holds a reference on a mount's behalf: children do not
pin their parent, a mount namespace holds none of its mounts, and a
parent does not hold its children, except for a vacant child, which is
described below.  Every other reference is a plain
one taken with mntget() or by legitimizing a mount during a path walk:
the path of an open file, the root and working directory of a task, a
pinned mountpoint during a mount operation.

While a mount is in a namespace (->mnt_ns is set) mntput() only
decrements the count.  The own reference is dropped no earlier than an
RCU grace period after ->mnt_ns was cleared, so a put that sees ->mnt_ns
set is never the last one and needs no lock.

umount_tree() takes a tree out of its namespace: ->mnt_ns is cleared,
MNT_UMOUNT is set, and every mount's own reference is moved to the
``unmounted`` list, whether the mount is disconnected from its parent or
stays attached to it.  A mount stays attached only to a parent that is
unmounted itself, because the mount is locked (MNT_LOCKED) or because the
tree was unmounted with UMOUNT_CONNECTED, which is what __detach_mounts()
asks for when a mountpoint directory is removed and what
dissolve_on_fput() asks for when a detached tree's last file is closed.
What stays attached
keeps covering its mountpoint: a path walk that reaches the dead parent
through an open file finds the child and never the directory the child
covers.

namespace_unlock() waits for an RCU grace period and then drops the own
references from task work, parents before children, each final put
followed by the cleanup of that mount.  A kernel thread, and a task that
is exiting, drop them in place and queue the cleanups.

The final put of an unmounted mount runs under mount_lock
(mntput_final_locked()).  A disconnected mount is marked MNT_DOOMED,
taken off its superblock's list of mounts and its children are unhashed;
they keep their own references and are cleaned up by their own final
put.  MNT_DOOMED is what a path walk that incremented the count of a
mount whose last reference went away in the meantime checks for under
mount_lock: it gives the increment back and restarts the walk.  A mount
that is still attached when its count reaches zero is vacated in place
instead, see below.  cleanup_mnt() then runs from task work: the fsnotify
marks are cleared, the root dentry is dropped, the superblock is
deactivated and the mount is freed after an RCU grace period.

Vacant mounts and knullfs
=========================

knullfs is a private instance of nullfs created at boot: a permanently
empty, immutable directory with SB_NOUSER set, part of no namespace,
which never goes away.  It is the root and working directory of kernel
threads and it is what a vacated mount points at.

A mount that loses its last reference while it is still attached to its
unmounted parent may not simply disappear, because that would reveal the
directory it covers.  It also may not be owned by its parent, because the
filesystem it carries may hold a file on the parent and the parent's own
death would then wait for the child's, which waits for the parent's: a
loop device with its image on the parent, a lower directory of ecryptfs,
a fuse passthrough file, a binfmt_misc interpreter and others form that
cycle.  So the mount is vacated: ->mnt_old_root keeps the root it was
mounted from, ->mnt_sb and ->mnt_root are pointed at knullfs, the mount
moves to knullfs' list of mounts, it becomes read-only and MNT_VACANT,
gets a fresh unique mount id, and it holds exactly one reference, which
belongs to its parent.  The release of the filesystem it carried is
queued as its cleanup.  A vacant mount takes no reference on knullfs.

What is found at the mountpoint from then on is an empty read-only
directory: lookups fail with ENOENT, nothing can be created in it, and
nothing can be mounted on it, since the mount is in no namespace.  Its
children were unhashed before it was vacated and it never gets new ones.
fanotify refuses mount and filesystem marks on it because knullfs has
SB_NOUSER; a mark placed before the vacate is accounted on the superblock
recorded in its connector and cleared by the release before that
superblock is torn down.

The parent lets go of a vacant mount in two ways.  Its own final put
unhashes all of its children and drops the reference of the vacant ones,
right after it drops mount_lock.  __detach_mounts(), when the mountpoint
directory is removed through the parent, unhashes the mount there and
collects a vacant one on the ``disowned`` list; namespace_unlock() drops
the parent's reference right after it releases namespace_sem, with no
grace period, since the mount left its namespace long ago.  A vacant
mount never rides the ``unmounted`` list: the first mount on that list
carries the task work in its ->mnt_rcu, and a vacant mount's ->mnt_rcu
may hold its pending release.

The last put of a vacant mount and the release of the filesystem it
carried can come in either order, and whichever comes second frees the
mount.  The last put sets MNT_DOOMED and frees the mount if
->mnt_old_root is already clear.  The release clears ->mnt_old_root
under mount_lock and frees the mount if MNT_DOOMED is already set.  Both
decisions are taken while mount_lock is held.

Ownership therefore only ever runs from a parent to a vacant child, and
nothing leads from a vacant mount back to another mount.  A subtree
nobody refers to collapses like a disconnected one, and a child whose
filesystem holds a file on an ancestor is released while it is still
attached, which drops the file and lets the ancestor go.

Cleanup order
=============

For an unmounted tree, in the order things happen:

1. umount_tree(): ->mnt_ns cleared, MNT_UMOUNT set, own references on
   ``unmounted``, mounts unhashed or left attached to their unmounted
   parent.
2. namespace_unlock(): the parent's references of the vacant mounts
   __detach_mounts() cut loose are dropped; then, if anything was
   unmounted, an RCU grace period and the own references dropped from
   task work in tree order.
3. Final put of a disconnected mount: MNT_DOOMED, children unhashed,
   cleanup_mnt() releases the filesystem and frees the mount after an
   RCU grace period.
4. Final put of an attached mount: vacated in place, the release of the
   filesystem it carried queued, the vacant children of the mount's own
   final put dropped after mount_lock.
5. Last put of a vacant mount, after its parent let go of it: MNT_DOOMED;
   the mount is freed by whichever of the last put and the release comes
   second.
