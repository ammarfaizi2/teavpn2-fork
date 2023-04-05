// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2023  Ammar Faizi <ammarfaizi2@gnuweeb.org>
 */

#ifndef TEAVPN2__SERVER__SERVER_H
#define TEAVPN2__SERVER__SERVER_H

#include <teavpn2/common.h>
#include <arpa/inet.h>

/*
 * Server socket configuration.
 */
struct srv_cfg_sock {
	bool		use_encryption;
	uint8_t		type;
	char		bind_addr[INET6_ADDRSTRLEN];
	uint16_t	bind_port;
	int		backlog;
	uint32_t	max_conn;
	char		event_loop[16];
	const char	*ssl_cert;
	const char	*ssl_priv_key;
};

/*
 * Server network configuration.
 */
struct srv_cfg_net {
	char		dev[16];
	uint16_t	mtu;
	char		ipv4[INET_ADDRSTRLEN];
	char		ipv6[INET6_ADDRSTRLEN];
};

/*
 * Server system configuration.
 */
struct srv_cfg_sys {
	const char	*cfg_file;
	const char	*data_dir;
	uint8_t		max_thread;
};

struct srv_cfg {
	struct srv_cfg_sys	sys;
	struct srv_cfg_net	net;
	struct srv_cfg_sock	sock;
};

extern int run_server(int argc, char *argv[]);

#endif /* #ifndef TEAVPN2__SERVER__SERVER_H */
