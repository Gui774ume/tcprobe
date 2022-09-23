/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
/* Copyright (c) 2020
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of version 2 of the GNU General Public
 * License as published by the Free Software Foundation.
 */
#ifndef _CACHE_FACTORY_H_
#define _CACHE_FACTORY_H_

#define STRUCT_ZERO_KEY 0

#define cache_factory(NAME, SIZE)                                                                                      \
                                                                                                                       \
    struct {                                                                                                           \
	    __uint(type, BPF_MAP_TYPE_HASH);                                                                               \
	    __type(key, u64);                                                                                              \
	    __type(value, struct NAME##_t);                                                                                \
	    __uint(max_entries, LEN);                                                                                      \
    } NAME##_cache SEC(".maps");                                                                                       \
                                                                                                                       \
    __attribute__((always_inline)) struct NAME##_t *peek_##NAME() {                                                    \
        u64 key = bpf_get_current_pid_tgid();                                                                          \
        struct NAME##_t *elem = bpf_map_lookup_elem(&NAME##_cache, &key);                                              \
        return elem;                                                                                                   \
    };                                                                                                                 \
                                                                                                                       \
    __attribute__((always_inline)) struct NAME##_t *pop_##NAME() {                                                     \
        u64 key = bpf_get_current_pid_tgid();                                                                          \
        struct NAME##_t *elem = bpf_map_lookup_elem(&NAME##_cache, &key);                                              \
        if (elem == NULL) {                                                                                            \
            return NULL;                                                                                               \
        }                                                                                                              \
        bpf_map_delete_elem(&NAME##_cache, &key);                                                                          \
        return elem;                                                                                                   \
    };                                                                                                                 \
                                                                                                                       \
    __attribute__((always_inline)) int cache_##NAME(struct NAME##_t *entry) {                                          \
        u64 key = bpf_get_current_pid_tgid();                                                                          \
        return bpf_map_update_elem(&NAME##_cache, &key, entry, BPF_ANY);                                               \
    };                                                                                                                 \

#endif