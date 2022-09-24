/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
/* Copyright (c) 2020
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of version 2 of the GNU General Public
 * License as published by the Free Software Foundation.
 */
#ifndef _CHAIN_H__
#define _CHAIN_H__

struct chain_t {
    u32 index;
    u32 padding;
};

__attribute__((always_inline)) void fill_chain(struct tcf_chain *c, struct chain_t *chain) {
    BPF_CORE_READ_INTO(&chain->index, c, index);
}

#endif