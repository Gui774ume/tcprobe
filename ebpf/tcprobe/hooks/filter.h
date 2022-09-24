/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
/* Copyright (c) 2020
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of version 2 of the GNU General Public
 * License as published by the Free Software Foundat`ion.
 */
#ifndef _FILTER_H_
#define _FILTER_H_

struct bpf_prog_t {
    u32 program_type;
    u32 attach_type;
    u32 id;
    u32 padding;
    char prog_name[BPF_OBJ_NAME_LEN]; // 16
    char tag[BPF_TAG_SIZE]; // 8
};

__attribute__((always_inline)) void fill_bpf_prog(struct bpf_prog *bp, struct bpf_prog_t *prog) {
    BPF_CORE_READ_INTO(&prog->program_type, bp, type);
    BPF_CORE_READ_INTO(&prog->attach_type, bp, expected_attach_type);
    BPF_CORE_READ_INTO(&prog->tag, bp, tag);
    BPF_CORE_READ_INTO(&prog->id, bp, aux, id);
    BPF_CORE_READ_INTO(&prog->prog_name, bp, aux, name);
}

struct cls_bpf_t {
    char cls_bpf_name[CLS_BPF_NAME_LEN_MAX]; // Should be CLS_BPF_NAME_LEN = 256 ...
    struct bpf_prog_t prog;
    struct bpf_prog_t old_prog;
};

struct tc_cls_bpf_offload {
	struct flow_cls_common_offload common;
	u32 command;
	struct tcf_exts *exts;
	struct bpf_prog *prog;
	struct bpf_prog *oldprog;
	const char *name;
	bool exts_integrated;
};

struct filter_t {
    u32 prio;
    u16 protocol;
    u16 padding1;
    u32 tc_setup_type;
    u32 handle;
    char kind[IFNAMSIZ];

    union {
        struct cls_bpf_t cls_bpf;
    };
};

__attribute__((always_inline)) void fill_tp(struct tcf_proto *tp, struct filter_t *filter) {
    BPF_CORE_READ_INTO(&filter->prio, tp, prio);
    filter->prio = filter->prio >> 16;
    BPF_CORE_READ_INTO(&filter->protocol, tp, protocol);
    BPF_CORE_READ_INTO(&filter->kind, tp, ops, kind);
}

__attribute__((always_inline)) void fill_cls_bpf(struct tc_cls_bpf_offload *cb, struct filter_t *filter) {
    // the handle of the bpf filter is right after the "struct tcf_exts exts" field in "struct cls_bpf_prog"
    u16 handle_offset = bpf_core_type_size(struct tcf_exts);
    struct tcf_exts *exts = NULL;
    bpf_probe_read(&exts, sizeof(exts), &cb->exts);
    bpf_probe_read(&filter->handle, sizeof(filter->handle), (void *)exts + handle_offset);

    char *name = NULL;
    bpf_probe_read(&name, sizeof(&name), &cb->name);
    bpf_probe_read_str(filter->cls_bpf.cls_bpf_name, sizeof(filter->cls_bpf.cls_bpf_name), name);

    struct bpf_prog *p = NULL;
    bpf_probe_read(&p, sizeof(p), &cb->prog);
    if (p != NULL) {
        fill_bpf_prog(p, &filter->cls_bpf.prog);
    }

    p = NULL;
    bpf_probe_read(&p, sizeof(p), &cb->oldprog);
    if (p != NULL) {
        fill_bpf_prog(p, &filter->cls_bpf.old_prog);
    }
}

struct filter_netlink_msg_t {
    struct network_interface_t netif;
    struct netlink_message_t netlink;
    struct qdisc_t qdisc;
    struct chain_t chain;
    struct block_t block;
    struct filter_t filter;
};

struct filter_cache_t {
    struct filter_netlink_msg_t msg;
    struct netlink_ext_ack *extack;
};

struct filter_event_t {
    struct kernel_event_t event;
    struct process_context_t process;
    struct filter_netlink_msg_t msg;
};

memory_factory(filter_event)
cache_factory(filter_cache, 1024)

SEC("kprobe/tc_new_tfilter")
int BPF_KPROBE(kprobe_tc_new_tfilter, struct sk_buff *skb, struct nlmsghdr *n, struct netlink_ext_ack *extack) {
    struct filter_cache_t entry = {
        .extack = extack,
    };

    // parse request parameters
    BPF_CORE_READ_INTO(&entry.msg.netif.netns, skb, sk, __sk_common.skc_net.net, ns.inum);
    struct tcmsg *tcm =(struct tcmsg *)((unsigned char *)n + NLMSG_HDRLEN);
    BPF_CORE_READ_INTO(&entry.msg.netif.ifindex, tcm, tcm_ifindex);
    BPF_CORE_READ_INTO(&entry.msg.qdisc.handle, tcm, tcm_parent);
    BPF_CORE_READ_INTO(&entry.msg.block.index, tcm, tcm_parent);
    fill_netlink_message(n, &entry.msg.netlink);

    BPF_CORE_READ_INTO(&entry.msg.filter.prio, tcm, tcm_info);
    entry.msg.filter.prio = TC_H_MAJ(entry.msg.filter.prio) >> 16;
    u32 protocol = 0;
    BPF_CORE_READ_INTO(&protocol, tcm, tcm_info);
    entry.msg.filter.protocol = TC_H_MIN(protocol);
    BPF_CORE_READ_INTO(&entry.msg.filter.handle, tcm, tcm_handle);

    put_filter_cache(&entry);
    return 0;
}

SEC("kretprobe/dev_get_by_index_rcu")
int BPF_KRETPROBE(kretprobe_dev_get_by_index_rcu, struct net_device *dev) {
    struct filter_cache_t *entry = peek_filter_cache();
    if (entry == NULL) {
        return 0;
    }

    if (dev == NULL) {
        return 0;
    }

    // read interface name
    fill_netif(dev, &entry->msg.netif);

    if (entry->msg.qdisc.handle == 0) {
        struct Qdisc *q = NULL;
        BPF_CORE_READ_INTO(&q, dev, qdisc);
        if (q != NULL) {
            fill_qdisc(q, &entry->msg.qdisc);
        }
    } else {
        entry->msg.qdisc.handle = TC_H_MAJ(entry->msg.qdisc.handle);
    }
    return 0;
}

SEC("kretprobe/qdisc_lookup_rcu")
int BPF_KRETPROBE(kretprobe_qdisc_lookup_rcu, struct Qdisc *q) {
    struct filter_cache_t *entry = peek_filter_cache();
    if (entry == NULL) {
        return 0;
    }

    if (q == NULL) {
        return 0;
    }

    fill_qdisc(q, &entry->msg.qdisc);
    return 0;
}

SEC("kretprobe/__tcf_block_find")
int BPF_KRETPROBE(kretprobe___tcf_block_find, struct tcf_block *b) {
    struct filter_cache_t *entry = peek_filter_cache();
    if (entry == NULL) {
        return 0;
    }

    if (b == NULL) {
        return 0;
    }

    fill_block(b, &entry->msg.block);
    entry->msg.block.classid = entry->msg.qdisc.handle;
    return 0;
}

SEC("kprobe/tcf_chain_tp_find")
int BPF_KPROBE(kprobe_tcf_chain_tp_find, struct tcf_chain *c, struct tcf_chain_info *chain_info, u32 protocol, u32 prio) {
    struct filter_cache_t *entry = peek_filter_cache();
    if (entry == NULL) {
        return 0;
    }

    entry->msg.filter.prio = prio >> 16;
    entry->msg.filter.protocol = protocol;

    if (c != NULL) {
        fill_chain(c, &entry->msg.chain);
    }
    return 0;
}

SEC("kretprobe/tcf_chain_tp_find")
int BPF_KPROBE(kretprobe_tcf_chain_tp_find, struct tcf_proto *tp) {
    struct filter_cache_t *entry = peek_filter_cache();
    if (entry == NULL) {
        return 0;
    }

    if (tp && !is_err(tp)) {
        fill_tp(tp, &entry->msg.filter);
        struct tcf_chain *c;
        BPF_CORE_READ_INTO(&c, tp, chain);
        if (c != NULL) {
            fill_chain(c, &entry->msg.chain);
            struct tcf_block *b;
            BPF_CORE_READ_INTO(&b, c, block);
            if (b != NULL) {
                fill_block(b, &entry->msg.block);
                struct Qdisc *q;
                BPF_CORE_READ_INTO(&q, b, q);
                if (q != NULL) {
                    fill_qdisc(q, &entry->msg.qdisc);
                }
            }
        }
    }
    return 0;
}

SEC("kprobe/tfilter_notify")
int BPF_KPROBE(kprobe_tfilter_notify, struct net *net, struct sk_buff *oskb, struct nlmsghdr *n, struct tcf_proto *tp, struct tcf_block *b) {
    struct filter_cache_t *entry = peek_filter_cache();
    if (entry == NULL) {
        return 0;
    }

    if (b != NULL) {
        fill_block(b, &entry->msg.block);
        struct Qdisc *q;
        BPF_CORE_READ_INTO(&q, b, q);
        if (q != NULL) {
            fill_qdisc(q, &entry->msg.qdisc);
        }
    }

    if (tp != NULL) {
        fill_tp(tp, &entry->msg.filter);
        struct tcf_chain *c;
        BPF_CORE_READ_INTO(&c, tp, chain);
        if (c != NULL) {
            fill_chain(c, &entry->msg.chain);
        }
    }

    return 0;
}

__attribute__((always_inline)) int trace_tc_setup_cb(struct tcf_block *b, struct tcf_proto *tp, enum tc_setup_type type, void *type_data) {
    struct filter_cache_t *entry = peek_filter_cache();
    if (entry == NULL) {
        return 0;
    }

    if (b != NULL) {
        fill_block(b, &entry->msg.block);
        struct Qdisc *q;
        BPF_CORE_READ_INTO(&q, b, q);
        if (q != NULL) {
            fill_qdisc(q, &entry->msg.qdisc);
        }
    }

    if (tp != NULL) {
        fill_tp(tp, &entry->msg.filter);
        struct tcf_chain *c;
        BPF_CORE_READ_INTO(&c, tp, chain);
        fill_chain(c, &entry->msg.chain);
    }

    // copy filter specific fields
    entry->msg.filter.tc_setup_type = type;
    
    if (type == TC_SETUP_CLSBPF) {
        struct tc_cls_bpf_offload *cls_bpf = (struct tc_cls_bpf_offload *)type_data;
        fill_cls_bpf(cls_bpf, &entry->msg.filter);
    }
    return 0;
}

SEC("kprobe/tc_setup_cb_add")
int BPF_KPROBE(kprobe_tc_setup_cb_add, struct tcf_block *b, struct tcf_proto *tp, enum tc_setup_type type, void *type_data) {
    return trace_tc_setup_cb(b, tp, type, type_data);
}

SEC("kprobe/tc_setup_cb_replace")
int BPF_KPROBE(kprobe_tc_setup_cb_replace, struct tcf_block *b, struct tcf_proto *tp, enum tc_setup_type type, void *type_data) {
    return trace_tc_setup_cb(b, tp, type, type_data);
}

SEC("kprobe/tc_setup_cb_destroy")
int BPF_KPROBE(kprobe_tc_setup_cb_destroy, struct tcf_block *b, struct tcf_proto *tp, enum tc_setup_type type, void *type_data) {
    return trace_tc_setup_cb(b, tp, type, type_data);
}

SEC("kretprobe/tc_new_tfilter")
int BPF_KRETPROBE(kretprobe_tc_new_tfilter, int retval) {
    struct filter_cache_t *entry = pop_filter_cache();
    if (entry == NULL) {
        return 0;
    }

    struct filter_event_t *event = new_filter_event();
    if (event == NULL) {
        // ignore, should not happen
        return 0;
    }
    event->event.type = EVENT_FILTER;
    event->event.retval = retval;
    event->msg = entry->msg;
    fill_process_context(&event->process);

    if (retval < 0) {

        // TODO: on failure, fallback to TCA variable attributes in order to help debug invalid input parameters.
        // See "RTM_NEWFILTER, RTM_DELFILTER, RTM_GETFILTER" at https://man7.org/linux/man-pages/man7/rtnetlink.7.html

        copy_netlink_error(entry->extack, &event->msg.netlink);
    }

    int perf_ret;
    send_event_ptr(ctx, event->event.type, event);
    return 0;
}

SEC("kprobe/tc_del_tfilter")
int BPF_KPROBE(kprobe_tc_del_tfilter, struct sk_buff *skb, struct nlmsghdr *n, struct netlink_ext_ack *extack) {
    struct filter_cache_t entry = {
        .extack = extack,
    };

    // parse request parameters
    BPF_CORE_READ_INTO(&entry.msg.netif.netns, skb, sk, __sk_common.skc_net.net, ns.inum);
    struct tcmsg *tcm =(struct tcmsg *)((unsigned char *)n + NLMSG_HDRLEN);
    BPF_CORE_READ_INTO(&entry.msg.netif.ifindex, tcm, tcm_ifindex);
    BPF_CORE_READ_INTO(&entry.msg.qdisc.handle, tcm, tcm_parent);
    BPF_CORE_READ_INTO(&entry.msg.block.index, tcm, tcm_parent);
    fill_netlink_message(n, &entry.msg.netlink);

    BPF_CORE_READ_INTO(&entry.msg.filter.prio, tcm, tcm_info);
    entry.msg.filter.prio = TC_H_MAJ(entry.msg.filter.prio) >> 16;
    u32 protocol = 0;
    BPF_CORE_READ_INTO(&protocol, tcm, tcm_info);
    entry.msg.filter.protocol = TC_H_MIN(protocol);
    BPF_CORE_READ_INTO(&entry.msg.filter.handle, tcm, tcm_handle);

    put_filter_cache(&entry);
    return 0;
}

SEC("kretprobe/tc_del_tfilter")
int BPF_KRETPROBE(kretprobe_tc_del_tfilter, int retval) {
    struct filter_cache_t *entry = pop_filter_cache();
    if (entry == NULL) {
        return 0;
    }

    struct filter_event_t *event = new_filter_event();
    if (event == NULL) {
        // ignore, should not happen
        return 0;
    }
    event->event.type = EVENT_FILTER;
    event->event.retval = retval;
    event->msg = entry->msg;
    fill_process_context(&event->process);

    if (retval < 0) {

        // TODO: on failure, fallback to TCA variable attributes in order to help debug invalid input parameters.
        // See "RTM_NEWFILTER, RTM_DELFILTER, RTM_GETFILTER" at https://man7.org/linux/man-pages/man7/rtnetlink.7.html

        copy_netlink_error(entry->extack, &event->msg.netlink);
    }

    int perf_ret;
    send_event_ptr(ctx, event->event.type, event);
    return 0;
}

SEC("kprobe/tc_get_tfilter")
int BPF_KPROBE(kprobe_tc_get_tfilter, struct sk_buff *skb, struct nlmsghdr *n, struct netlink_ext_ack *extack) {
    struct filter_cache_t entry = {
        .extack = extack,
    };

    // parse request parameters
    BPF_CORE_READ_INTO(&entry.msg.netif.netns, skb, sk, __sk_common.skc_net.net, ns.inum);
    struct tcmsg *tcm =(struct tcmsg *)((unsigned char *)n + NLMSG_HDRLEN);
    BPF_CORE_READ_INTO(&entry.msg.netif.ifindex, tcm, tcm_ifindex);
    BPF_CORE_READ_INTO(&entry.msg.qdisc.handle, tcm, tcm_parent);
    BPF_CORE_READ_INTO(&entry.msg.block.index, tcm, tcm_parent);
    fill_netlink_message(n, &entry.msg.netlink);

    BPF_CORE_READ_INTO(&entry.msg.filter.prio, tcm, tcm_info);
    entry.msg.filter.prio = TC_H_MAJ(entry.msg.filter.prio) >> 16;
    u32 protocol = 0;
    BPF_CORE_READ_INTO(&protocol, tcm, tcm_info);
    entry.msg.filter.protocol = TC_H_MIN(protocol);
    BPF_CORE_READ_INTO(&entry.msg.filter.handle, tcm, tcm_handle);

    put_filter_cache(&entry);
    return 0;
}

SEC("kretprobe/tc_get_tfilter")
int BPF_KRETPROBE(kretprobe_tc_get_tfilter, int retval) {
    struct filter_cache_t *entry = pop_filter_cache();
    if (entry == NULL) {
        return 0;
    }

    struct filter_event_t *event = new_filter_event();
    if (event == NULL) {
        // ignore, should not happen
        return 0;
    }
    event->event.type = EVENT_FILTER;
    event->event.retval = retval;
    event->msg = entry->msg;
    fill_process_context(&event->process);

    if (retval < 0) {

        // TODO: on failure, fallback to TCA variable attributes in order to help debug invalid input parameters.
        // See "RTM_NEWFILTER, RTM_DELFILTER, RTM_GETFILTER" at https://man7.org/linux/man-pages/man7/rtnetlink.7.html

        copy_netlink_error(entry->extack, &event->msg.netlink);
    }

    int perf_ret;
    send_event_ptr(ctx, event->event.type, event);
    return 0;
}

#endif
