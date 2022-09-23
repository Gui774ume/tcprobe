/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
/* Copyright (c) 2020
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of version 2 of the GNU General Public
 * License as published by the Free Software Foundation.
 */
#ifndef _QDISC_H_
#define _QDISC_H_

#define NLMSG_ALIGNTO	 4U
#define NLMSG_ALIGN(len) ( ((len)+NLMSG_ALIGNTO-1) & ~(NLMSG_ALIGNTO-1) )
#define NLMSG_HDRLEN	 ((int) NLMSG_ALIGN(sizeof(struct nlmsghdr)))

#define TC_H_ROOT	     (0xFFFFFFFFU)
#define TC_H_INGRESS     (0xFFFFFFF1U)

struct qdisc_t {
    u32 netns;
    u32 ifindex;
    char ifname[IFNAMSIZ];

    u32 handle;
    u32 parent;
    char qdisc_id[IFNAMSIZ];

    u16 nlmsg_type;
    u16 nlmsg_flags;
    u32 padding;
};

struct qdisc_ctx_t {
    struct qdisc_t qdisc;

    struct netlink_ext_ack *extack;
};

#define NETLINK_ERROR_MSG_LEN 64

struct qdisc_event_t {
    struct kernel_event_t event;
    struct process_context_t process;
    struct qdisc_t qdisc;
    char netlink_error_msg[NETLINK_ERROR_MSG_LEN];
};

memory_factory(qdisc_event)
cache_factory(qdisc_ctx, 1024)

SEC("kprobe/tc_modify_qdisc")
int BPF_KPROBE(kprobe_tc_modify_qdisc, struct sk_buff *skb, struct nlmsghdr *n, struct netlink_ext_ack *extack) {
    struct qdisc_ctx_t entry = {
        .extack = extack,
    };

    // parse request parameters
    BPF_CORE_READ_INTO(&entry.qdisc.netns, skb, sk, __sk_common.skc_net.net, ns.inum);
    struct tcmsg *tcm =(struct tcmsg *)((unsigned char *)n + NLMSG_HDRLEN);
    BPF_CORE_READ_INTO(&entry.qdisc.ifindex, tcm, tcm_ifindex);
    BPF_CORE_READ_INTO(&entry.qdisc.handle, tcm, tcm_handle);
    BPF_CORE_READ_INTO(&entry.qdisc.parent, tcm, tcm_parent);
    BPF_CORE_READ_INTO(&entry.qdisc.nlmsg_type, n, nlmsg_type);
    BPF_CORE_READ_INTO(&entry.qdisc.nlmsg_flags, n, nlmsg_flags);

    cache_qdisc_ctx(&entry);
    return 0;
}

SEC("kretprobe/__dev_get_by_index")
int BPF_KRETPROBE(kretprobe___dev_get_by_index, struct net_device *dev) {
    struct qdisc_ctx_t *entry = peek_qdisc_ctx();
    if (entry == NULL) {
        return 0;
    }

    if (dev == NULL) {
        return 0;
    }

    // read interface name
    BPF_CORE_READ_INTO(&entry->qdisc.ifname, dev, name);
    BPF_CORE_READ_INTO(&entry->qdisc.ifindex, dev, ifindex);

    if (entry->qdisc.parent == TC_H_ROOT) {
        struct Qdisc *q = NULL;
        BPF_CORE_READ_INTO(&q, dev, qdisc);
        BPF_CORE_READ_INTO(&entry->qdisc.qdisc_id, q, ops, id);
        BPF_CORE_READ_INTO(&entry->qdisc.handle, q, handle);
        BPF_CORE_READ_INTO(&entry->qdisc.parent, q, parent);
    }
    return 0;
}

SEC("kretprobe/qdisc_create")
int BPF_KRETPROBE(kretprobe_qdisc_create, struct Qdisc *q) {
    struct qdisc_ctx_t *entry = peek_qdisc_ctx();
    if (entry == NULL) {
        return 0;
    }

    if (q == NULL) {
        return 0;
    }

    // read qdisc identification values
    BPF_CORE_READ_INTO(&entry->qdisc.qdisc_id, q, ops, id);
    BPF_CORE_READ_INTO(&entry->qdisc.handle, q, handle);
    BPF_CORE_READ_INTO(&entry->qdisc.parent, q, parent);
    return 0;
}

SEC("kretprobe/dev_ingress_queue_create")
int BPF_KRETPROBE(kretprobe_dev_ingress_queue_create, struct netdev_queue *queue) {
    struct qdisc_ctx_t *entry = peek_qdisc_ctx();
    if (entry == NULL) {
        return 0;
    }

    if (queue == NULL) {
        return 0;
    }

    // read qdisc identification values
    struct Qdisc *q = NULL;
    BPF_CORE_READ_INTO(&q, queue, qdisc_sleeping);
    BPF_CORE_READ_INTO(&entry->qdisc.qdisc_id, q, ops, id);
    BPF_CORE_READ_INTO(&entry->qdisc.handle, q, handle);
    BPF_CORE_READ_INTO(&entry->qdisc.parent, q, parent);
    return 0;
}

SEC("kretprobe/qdisc_lookup")
int BPF_KRETPROBE(kretprobe_qdisc_lookup, struct Qdisc *q) {
    struct qdisc_ctx_t *entry = peek_qdisc_ctx();
    if (entry == NULL) {
        return 0;
    }

    if (q == NULL) {
        return 0;
    }

    // read qdisc identification values
    BPF_CORE_READ_INTO(&entry->qdisc.qdisc_id, q, ops, id);
    BPF_CORE_READ_INTO(&entry->qdisc.handle, q, handle);
    BPF_CORE_READ_INTO(&entry->qdisc.parent, q, parent);
    return 0;
}

SEC("kretprobe/qdisc_leaf")
int BPF_KRETPROBE(kretprobe_qdisc_leaf, struct Qdisc *q) {
    struct qdisc_ctx_t *entry = peek_qdisc_ctx();
    if (entry == NULL) {
        return 0;
    }

    if (q == NULL) {
        return 0;
    }

    // read qdisc identification values
    BPF_CORE_READ_INTO(&entry->qdisc.qdisc_id, q, ops, id);
    BPF_CORE_READ_INTO(&entry->qdisc.handle, q, handle);
    BPF_CORE_READ_INTO(&entry->qdisc.parent, q, parent);
    return 0;
}

SEC("kretprobe/tc_modify_qdisc")
int BPF_KRETPROBE(kretprobe_tc_modify_qdisc, int retval) {
    struct qdisc_ctx_t *entry = pop_qdisc_ctx();
    if (entry == NULL) {
        return 0;
    }

    struct qdisc_event_t *event = new_qdisc_event();
    if (event == NULL) {
        // ignore, should not happen
        return 0;
    }
    event->event.type = EVENT_QDISC;
    event->event.retval = retval;
    event->qdisc = entry->qdisc;
    fill_process_context(&event->process);

    u8 error_msg_len = 0;
    if (retval < 0) {

        // TODO: on failure, fallback to TCA variable attributes in order to help debug invalid input parameters.
        // See "RTM_NEWQDISC, RTM_DELQDISC, RTM_GETQDISC" at https://man7.org/linux/man-pages/man7/rtnetlink.7.html

        char *msg = 0;
        struct netlink_ext_ack *extack = entry->extack;
        BPF_CORE_READ_INTO(&msg, extack, _msg);
        error_msg_len = bpf_probe_read_str(event->netlink_error_msg, sizeof(event->netlink_error_msg), msg);
    }

    int perf_ret;
    send_event_with_size_ptr_perf(ctx, event->event.type, event, offsetof(struct qdisc_event_t, netlink_error_msg) + (error_msg_len & (NETLINK_ERROR_MSG_LEN - 1)));
    return 0;
}

SEC("kprobe/tc_get_qdisc")
int BPF_KPROBE(kprobe_tc_get_qdisc, struct sk_buff *skb, struct nlmsghdr *n, struct netlink_ext_ack *extack) {
    struct qdisc_ctx_t entry = {
        .extack = extack,
    };

    // parse request parameters
    BPF_CORE_READ_INTO(&entry.qdisc.netns, skb, sk, __sk_common.skc_net.net, ns.inum);
    struct tcmsg *tcm =(struct tcmsg *)((unsigned char *)n + NLMSG_HDRLEN);
    BPF_CORE_READ_INTO(&entry.qdisc.ifindex, tcm, tcm_ifindex);
    BPF_CORE_READ_INTO(&entry.qdisc.handle, tcm, tcm_handle);
    BPF_CORE_READ_INTO(&entry.qdisc.parent, tcm, tcm_parent);
    BPF_CORE_READ_INTO(&entry.qdisc.nlmsg_type, n, nlmsg_type);
    BPF_CORE_READ_INTO(&entry.qdisc.nlmsg_flags, n, nlmsg_flags);

    cache_qdisc_ctx(&entry);
    return 0;
}

SEC("kprobe/qdisc_destroy")
int BPF_KPROBE(kprobe_qdisc_destroy, struct Qdisc *q) {
    struct qdisc_ctx_t *entry = peek_qdisc_ctx();
    if (entry == NULL) {
        return 0;
    }

    if (q == NULL) {
        return 0;
    }

    // read qdisc identification values
    BPF_CORE_READ_INTO(&entry->qdisc.qdisc_id, q, ops, id);
    BPF_CORE_READ_INTO(&entry->qdisc.handle, q, handle);
    BPF_CORE_READ_INTO(&entry->qdisc.parent, q, parent);
    return 0;
}

SEC("kretprobe/tc_get_qdisc")
int BPF_KRETPROBE(kretprobe_tc_get_qdisc, int retval) {
    struct qdisc_ctx_t *entry = pop_qdisc_ctx();
    if (entry == NULL) {
        return 0;
    }

    struct qdisc_event_t *event = new_qdisc_event();
    if (event == NULL) {
        // ignore, should not happen
        return 0;
    }
    event->event.type = EVENT_QDISC;
    event->event.retval = retval;
    event->qdisc = entry->qdisc;
    fill_process_context(&event->process);

    u8 error_msg_len = 0;
    if (retval < 0) {

        // TODO: on failure, fallback to TCA variable attributes in order to help debug invalid input parameters.
        // See "RTM_NEWQDISC, RTM_DELQDISC, RTM_GETQDISC" at https://man7.org/linux/man-pages/man7/rtnetlink.7.html

        char *msg = 0;
        struct netlink_ext_ack *extack = entry->extack;
        BPF_CORE_READ_INTO(&msg, extack, _msg);
        error_msg_len = bpf_probe_read_str(event->netlink_error_msg, sizeof(event->netlink_error_msg), msg);
    }

    int perf_ret;
    send_event_with_size_ptr_perf(ctx, event->event.type, event, offsetof(struct qdisc_event_t, netlink_error_msg) + (error_msg_len & (NETLINK_ERROR_MSG_LEN - 1)));
    return 0;
}

#endif
