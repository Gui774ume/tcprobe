/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
/* Copyright (c) 2020
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of version 2 of the GNU General Public
 * License as published by the Free Software Foundation.
 */
#ifndef _BLOCK_H__
#define _BLOCK_H__

struct block_t {
    u32 index;
    u32 classid;
};

__attribute__((always_inline)) void fill_block(struct tcf_block *b, struct block_t *block) {
    BPF_CORE_READ_INTO(&block->index, b, index);
    BPF_CORE_READ_INTO(&block->classid, b, classid);
}

#endif