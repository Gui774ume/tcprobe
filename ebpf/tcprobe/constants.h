/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
/* Copyright (c) 2020
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of version 2 of the GNU General Public
 * License as published by the Free Software Foundation.
 */
#ifndef _CONSTANTS_H
#define _CONSTANTS_H

#define CGROUP_MAX_LENGTH 128
#define TASK_COMM_LEN 16
#define IFNAMSIZ 16
#define NETLINK_ERROR_MSG_LEN 64
#define BPF_OBJ_NAME_LEN 16
#define BPF_TAG_SIZE 8
#define CLS_BPF_NAME_LEN_MAX 128
#define CGROUP_SUBSYS_COUNT 15

#define LOAD_CONSTANT(param, var) asm("%0 = " param " ll" : "=r"(var))

#define NLMSG_ALIGNTO	 4U
#define NLMSG_ALIGN(len) ( ((len)+NLMSG_ALIGNTO-1) & ~(NLMSG_ALIGNTO-1) )
#define NLMSG_HDRLEN	 ((int) NLMSG_ALIGN(sizeof(struct nlmsghdr)))

#define TC_H_ROOT	     (0xFFFFFFFFU)
#define TC_H_INGRESS     (0xFFFFFFF1U)

#define TC_H_MAJ_MASK (0xFFFF0000U)
#define TC_H_MIN_MASK (0x0000FFFFU)
#define TC_H_MAJ(h) ((h)&TC_H_MAJ_MASK)
#define TC_H_MIN(h) ((h)&TC_H_MIN_MASK)

/*
 * Kernel pointers have redundant information, so we can use a
 * scheme where we can return either an error code or a normal
 * pointer with the same return value.
 *
 * This should be a per-architecture thing, to allow different
 * error and pointer decisions.
 */
#define MAX_ERRNO	4095
#define IS_ERR_VALUE(x) ((unsigned long)(void *)(x) < (unsigned long)-MAX_ERRNO)

__attribute__((always_inline)) bool is_err(const void *ptr) {
	return IS_ERR_VALUE((unsigned long)ptr);
}

//__attribute__((always_inline)) u64 get_raw_syscall_tracepoint_fallback() {
//    u64 raw_syscall_tracepoint_fallback;
//    LOAD_CONSTANT("raw_syscall_tracepoint_fallback", raw_syscall_tracepoint_fallback);
//    return raw_syscall_tracepoint_fallback;
//};

#endif
