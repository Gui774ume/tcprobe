/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
/* Copyright (c) 2020
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of version 2 of the GNU General Public
 * License as published by the Free Software Foundation.
 */

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wunused-but-set-variable"

// Custom eBPF helpers
#include "include/all.h"

// tcprobe probes
#include "tcprobe/memory_factory.h"
#include "tcprobe/cache_factory.h"
#include "tcprobe/constants.h"
#include "tcprobe/events.h"
#include "tcprobe/process.h"
#include "tcprobe/hooks/all_hooks.h"

#pragma clang diagnostic pop

char _license[] SEC("license") = "GPL";
__u32 _version SEC("version") = 0xFFFFFFFE;
