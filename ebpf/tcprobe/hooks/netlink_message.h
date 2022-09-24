/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
/* Copyright (c) 2020
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of version 2 of the GNU General Public
 * License as published by the Free Software Foundation.
 */
#ifndef _NETLINK_MESSAGE_H__
#define _NETLINK_MESSAGE_H__

struct netlink_message_t {
    u16 nlmsg_type;
    u16 nlmsg_flags;
    u32 padding;
    char netlink_error_msg[NETLINK_ERROR_MSG_LEN];
};

__attribute__((always_inline)) void fill_netlink_message(struct nlmsghdr *n, struct netlink_message_t *msg) {
    BPF_CORE_READ_INTO(&msg->nlmsg_type, n, nlmsg_type);
    BPF_CORE_READ_INTO(&msg->nlmsg_flags, n, nlmsg_flags);
}

__attribute__((always_inline)) void copy_netlink_error(struct netlink_ext_ack *extack, struct netlink_message_t *msg) {
    char *stack_msg_ptr = 0;
    BPF_CORE_READ_INTO(&stack_msg_ptr, extack, _msg);
    bpf_probe_read_str(msg->netlink_error_msg, sizeof(msg->netlink_error_msg), stack_msg_ptr);
}

#endif