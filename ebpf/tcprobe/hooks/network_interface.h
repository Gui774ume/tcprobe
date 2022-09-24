/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
/* Copyright (c) 2020
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of version 2 of the GNU General Public
 * License as published by the Free Software Foundation.
 */
#ifndef _NETWORK_INTERFACE_H__
#define _NETWORK_INTERFACE_H__

struct network_interface_t {
    u32 netns;
    u32 ifindex;
    char ifname[IFNAMSIZ];
};

__attribute__((always_inline)) void fill_netif(struct net_device *dev, struct network_interface_t *netif) {
    BPF_CORE_READ_INTO(&netif->ifname, dev, name);
    BPF_CORE_READ_INTO(&netif->ifindex, dev, ifindex);
    if (netif->netns == 0) {
        BPF_CORE_READ_INTO(&netif->netns, dev, nd_net.net, ns.inum);
    }
}

#endif