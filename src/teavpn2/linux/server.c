// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2023  Ammar Faizi <ammarfaizi2@gnuweeb.org>
 */

#include <teavpn2/server.h>

int run_server_app(struct srv_cfg *cfg)
{
	switch (cfg->sock.type) {
	case SOCK_TYPE_UDP:
		return run_server_udp(cfg);
		break;
	case SOCK_TYPE_TCP:
		pr_err("TCP socket is currently not supported!");
		return -EPROTONOSUPPORT;
	default:
		pr_err("Invalid socket type: %hhu", cfg->sock.type);
		return -EINVAL;
	}
}
