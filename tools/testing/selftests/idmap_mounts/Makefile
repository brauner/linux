# SPDX-License-Identifier: GPL-2.0
# Makefile for mount selftests.
CFLAGS = -g -I../../../../usr/include/ -Wall -O2 -pthread

TEST_GEN_FILES = xattr
TEST_GEN_FILES += core
TEST_GEN_FILES += stub

include ../lib.mk

$(OUTPUT)/xattr: xattr.c internal.h utils.c utils.h
$(OUTPUT)/core: core.c internal.h utils.c utils.h
$(OUTPUT)/stub: stub.c internal.h
