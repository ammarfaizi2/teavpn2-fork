// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2023  Ammar Faizi <ammarfaizi2@gnuweeb.org>
 * Copyright (C) 2023  Alviro Iskandar Setiawan <alviro.iskandar@gnuweeb.org>
 */

#ifndef TEAVPN2__AP__LINUX__SERVER_H
#define TEAVPN2__AP__LINUX__SERVER_H

#include <pthread.h>
#include <stdatomic.h>
#include <teavpn2/server.h>
#include <teavpn2/packet.h>
#include <teavpn2/helpers.h>

struct client_tcp {
	/*
	 * The TCP file descriptor of this client.
	 */
	int			fd;

	/*
	 * The source address of this client.
	 */
	struct sockaddr_storage	src;

	/*
	 * Number of bytes received and transmitted.
	 */
	uint64_t		nrx;
	uint64_t		ntx;

	bool			is_authenticated;

	/*
	 * spkt = Server packet buffer (for sending).
	 * cpkt = Client packet buffer (for receiving).
	 */
	uint16_t		spkt_len;
	uint16_t		cpkt_len;
	struct pkt		spkt;
	struct pkt		cpkt;
};

struct srv_ctx_tcp;

struct srv_wrk_tcp {
	int			epoll_fd;
	int			tun_fd;

	/*
	 * The timeout for epoll_wait() in milliseconds.
	 */
	int			ep_timeout;

	struct srv_ctx_tcp	*ctx;
	struct epoll_event	*events;

	uint8_t			tid;
	pthread_t		thread;
	_Atomic(uint32_t)	nr_fds;
};

struct srv_ctx_tcp {
	volatile bool		stop;
	int			tcp_fd;
	int			*tun_fds;

	struct sockaddr_storage	bind_addr;
	struct client_tcp	*clients;
	mutex_t			clients_lock;

	struct srv_wrk_tcp	*workers;
	struct srv_cfg		*cfg;

	_Atomic(uint32_t)	online_workers;
};

enum {
	EVT_EPOLL,
	EVT_IO_URING,
};

int select_server_event_loop(struct srv_cfg *cfg);
int run_server_app(struct srv_cfg *cfg);
int run_server_udp(struct srv_cfg *cfg);
int run_server_tcp(struct srv_cfg *cfg);
int run_server_tcp_epoll(struct srv_ctx_tcp *ctx);
int install_signal_stop_handler(volatile bool *stop);

#endif /* #ifndef TEAVPN2__AP__LINUX__SERVER_H */
