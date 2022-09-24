/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
/* Copyright (c) 2020
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of version 2 of the GNU General Public
 * License as published by the Free Software Foundation.
 */
#ifndef _QDISC_H_
#define _QDISC_H_

struct qdisc_t {
    u32 handle;
    u32 parent;
    char qdisc_id[IFNAMSIZ];
};

__attribute__((always_inline)) void fill_qdisc(struct Qdisc *q, struct qdisc_t *qdisc) {
    BPF_CORE_READ_INTO(&qdisc->qdisc_id, q, ops, id);
    BPF_CORE_READ_INTO(&qdisc->handle, q, handle);
    BPF_CORE_READ_INTO(&qdisc->parent, q, parent);
}

struct qdisc_netlink_msg_t {
    struct network_interface_t netif;
    struct netlink_message_t netlink;
    struct qdisc_t qdisc;
};

struct qdisc_cache_t {
    struct qdisc_netlink_msg_t msg;
    struct netlink_ext_ack *extack;
};

#define NETLINK_ERROR_MSG_LEN 64

struct qdisc_event_t {
    struct kernel_event_t event;
    struct process_context_t process;
    struct qdisc_netlink_msg_t msg;
};

memory_factory(qdisc_event)
cache_factory(qdisc_cache, 1024)

SEC("kprobe/tc_modify_qdisc")
int BPF_KPROBE(kprobe_tc_modify_qdisc, struct sk_buff *skb, struct nlmsghdr *n, struct netlink_ext_ack *extack) {
    struct qdisc_cache_t entry = {
        .extack = extack,
    };

    // parse request parameters
    BPF_CORE_READ_INTO(&entry.msg.netif.netns, skb, sk, __sk_common.skc_net.net, ns.inum);
    struct tcmsg *tcm =(struct tcmsg *)((unsigned char *)n + NLMSG_HDRLEN);
    BPF_CORE_READ_INTO(&entry.msg.netif.ifindex, tcm, tcm_ifindex);
    BPF_CORE_READ_INTO(&entry.msg.qdisc.handle, tcm, tcm_handle);
    BPF_CORE_READ_INTO(&entry.msg.qdisc.parent, tcm, tcm_parent);
    fill_netlink_message(n, &entry.msg.netlink);

    put_qdisc_cache(&entry);
    return 0;
}

SEC("kretprobe/__dev_get_by_index")
int BPF_KRETPROBE(kretprobe___dev_get_by_index, struct net_device *dev) {
    struct qdisc_cache_t *entry = peek_qdisc_cache();
    if (entry == NULL) {
        return 0;
    }

    if (dev == NULL) {
        return 0;
    }

    // read interface name
    fill_netif(dev, &entry->msg.netif);

    if (entry->msg.qdisc.parent == TC_H_ROOT) {
        struct Qdisc *q = NULL;
        BPF_CORE_READ_INTO(&q, dev, qdisc);
        if (q != NULL) {
            fill_qdisc(q, &entry->msg.qdisc);
        }
    }
    return 0;
}

SEC("kretprobe/qdisc_create")
int BPF_KRETPROBE(kretprobe_qdisc_create, struct Qdisc *q) {
    struct qdisc_cache_t *entry = peek_qdisc_cache();
    if (entry == NULL) {
        return 0;
    }

    if (q == NULL) {
        return 0;
    }

    // read qdisc identification values
    fill_qdisc(q, &entry->msg.qdisc);
    return 0;
}

SEC("kretprobe/dev_ingress_queue_create")
int BPF_KRETPROBE(kretprobe_dev_ingress_queue_create, struct netdev_queue *queue) {
    struct qdisc_cache_t *entry = peek_qdisc_cache();
    if (entry == NULL) {
        return 0;
    }

    if (queue == NULL) {
        return 0;
    }

    // read qdisc identification values
    struct Qdisc *q = NULL;
    BPF_CORE_READ_INTO(&q, queue, qdisc_sleeping);
    fill_qdisc(q, &entry->msg.qdisc);
    return 0;
}

SEC("kretprobe/qdisc_lookup")
int BPF_KRETPROBE(kretprobe_qdisc_lookup, struct Qdisc *q) {
    struct qdisc_cache_t *entry = peek_qdisc_cache();
    if (entry == NULL) {
        return 0;
    }

    if (q == NULL) {
        return 0;
    }

    // read qdisc identification values
    fill_qdisc(q, &entry->msg.qdisc);
    return 0;
}

SEC("kretprobe/qdisc_leaf")
int BPF_KRETPROBE(kretprobe_qdisc_leaf, struct Qdisc *q) {
    struct qdisc_cache_t *entry = peek_qdisc_cache();
    if (entry == NULL) {
        return 0;
    }

    if (q == NULL) {
        return 0;
    }

    // read qdisc identification values
    fill_qdisc(q, &entry->msg.qdisc);
    return 0;
}

SEC("kretprobe/tc_modify_qdisc")
int BPF_KRETPROBE(kretprobe_tc_modify_qdisc, int retval) {
    struct qdisc_cache_t *entry = pop_qdisc_cache();
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
    event->msg = entry->msg;
    fill_process_context(&event->process);

    if (retval < 0) {

        // TODO: on failure, fallback to TCA variable attributes in order to help debug invalid input parameters.
        // See "RTM_NEWQDISC, RTM_DELQDISC, RTM_GETQDISC" at https://man7.org/linux/man-pages/man7/rtnetlink.7.html

        copy_netlink_error(entry->extack, &event->msg.netlink);
    }

    int perf_ret;
    send_event_ptr(ctx, event->event.type, event);
    return 0;
}

SEC("kprobe/tc_get_qdisc")
int BPF_KPROBE(kprobe_tc_get_qdisc, struct sk_buff *skb, struct nlmsghdr *n, struct netlink_ext_ack *extack) {
    struct qdisc_cache_t entry = {
        .extack = extack,
    };

    // parse request parameters
    BPF_CORE_READ_INTO(&entry.msg.netif.netns, skb, sk, __sk_common.skc_net.net, ns.inum);
    struct tcmsg *tcm =(struct tcmsg *)((unsigned char *)n + NLMSG_HDRLEN);
    BPF_CORE_READ_INTO(&entry.msg.netif.ifindex, tcm, tcm_ifindex);
    BPF_CORE_READ_INTO(&entry.msg.qdisc.handle, tcm, tcm_handle);
    BPF_CORE_READ_INTO(&entry.msg.qdisc.parent, tcm, tcm_parent);
    fill_netlink_message(n, &entry.msg.netlink);

    put_qdisc_cache(&entry);
    return 0;
}

SEC("kprobe/qdisc_destroy")
int BPF_KPROBE(kprobe_qdisc_destroy, struct Qdisc *q) {
    struct qdisc_cache_t *entry = peek_qdisc_cache();
    if (entry == NULL) {
        return 0;
    }

    if (q == NULL) {
        return 0;
    }

    // read qdisc identification values
    fill_qdisc(q, &entry->msg.qdisc);
    return 0;
}

SEC("kretprobe/tc_get_qdisc")
int BPF_KRETPROBE(kretprobe_tc_get_qdisc, int retval) {
    struct qdisc_cache_t *entry = pop_qdisc_cache();
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
    event->msg = entry->msg;
    fill_process_context(&event->process);

    if (retval < 0) {

        // TODO: on failure, fallback to TCA variable attributes in order to help debug invalid input parameters.
        // See "RTM_NEWQDISC, RTM_DELQDISC, RTM_GETQDISC" at https://man7.org/linux/man-pages/man7/rtnetlink.7.html

        copy_netlink_error(entry->extack, &event->msg.netlink);
    }

    int perf_ret;
    send_event_ptr(ctx, event->event.type, event);
    return 0;
}

#endif
