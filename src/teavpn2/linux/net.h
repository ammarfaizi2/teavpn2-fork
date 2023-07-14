// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2023  Ammar Faizi <ammarfaizi2@gnuweeb.org>
 */

#ifndef TEAVPN2__AP__LINUX__NET_H
#define TEAVPN2__AP__LINUX__NET_H

#include <linux/if_tun.h>

int tun_alloc(const char *dev, short flags);

#endif
