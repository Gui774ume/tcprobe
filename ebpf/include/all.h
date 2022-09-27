/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
/* Copyright (c) 2020
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of version 2 of the GNU General Public
 * License as published by the Free Software Foundation.
 */
#ifndef _ALL_H__
#define _ALL_H__

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Waddress-of-packed-member"
#pragma clang diagnostic ignored "-Warray-bounds"
#pragma clang diagnostic ignored "-Wunused-label"
#pragma clang diagnostic ignored "-Wunknown-attributes"
#pragma clang diagnostic ignored "-Wgnu-variable-sized-type-not-at-end"
#pragma clang diagnostic ignored "-Wframe-address"

#if defined(__TARGET_ARCH_x86)
#include "vmlinux_x86.h"
#elif defined(__TARGET_ARCH_arm64)
#include "vmlinux_arm64.h"
#else
#error "No vmlinux.h available for this __TARGET_ARCH_xx"
#endif

#include "bpf_helpers.h"
#include "bpf_tracing.h"
// #include <errno.h>

#pragma clang diagnostic pop

#include "bpf_core_read.h"

#endif
