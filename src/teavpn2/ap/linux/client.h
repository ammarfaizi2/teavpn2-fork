// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2023  Ammar Faizi <ammarfaizi2@gnuweeb.org>
 */

#ifndef TEAVPN2__AP__LINUX__CLIENT_H
#define TEAVPN2__AP__LINUX__CLIENT_H

#include <teavpn2/common.h>
#include <teavpn2/client.h>

struct cli_cfg;

extern int run_server_app(struct cli_cfg *cfg);

#endif /* #ifndef TEAVPN2__AP__LINUX__CLIENT_H */
