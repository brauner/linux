// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2023 Christian Brauner.
 */

#ifndef BTRFS_FS_CONTEXT_H
#define BTRFS_FS_CONTEXT_H

#include <linux/btrfs.h>
#include <linux/fs.h>
#include <linux/fs_context.h>
#include <linux/fs_parser.h>
#include "fs.h"

extern const struct fs_parameter_spec btrfs_parameter_spec[];

int btrfs_fs_params_verify(struct btrfs_fs_info *info, struct fs_context *fc);
int btrfs_get_tree(struct fs_context *fc);
int btrfs_init_fs_context(struct fs_context *fc);

#endif
