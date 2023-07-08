// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2023  Ammar Faizi <ammarfaizi2@gnuweeb.org>
 * Copyright (C) 2023  Alviro Iskandar Setiawan <alviro.iskandar@gnuweeb.org>
 */

#ifndef TEAVPN2__AP__LINUX__SERVER_H
#define TEAVPN2__AP__LINUX__SERVER_H

#include <teavpn2/common.h>
#include <teavpn2/server.h>
#include <teavpn2/packet.h>
#include <teavpn2/helpers.h>
#include <teavpn2/server/helpers.h>
#include <time.h>

struct srv_cfg;

/*
 * UDP session. For each connected client is represented
 * by this struct.
 */
struct udp_sess {
	/*
	 * Client source address. Used to call sendto() and
	 * hash table lookup.
	 */
	struct sockaddr_storage		src_addr;

	/* 
	 * Client's private IPv4 address.
	 */
	union {
		uint8_t			__ipv4[4];
		struct in_addr		ipv4;
	};

	/*
	 * Client's private IPv6 address.
	 */
	union {
		uint8_t			__ipv6[16];
		struct in6_addr		ipv6;
	};

	/*
	 * UDP sessions are stored in an array. This is the
	 * index of the corresponding session. Useful for
	 * the put operation.
	 */
	uint16_t			idx;

	/*
	 * @rx_pkt length.
	 */
	uint16_t			rx_pkt_len;

	/*
	 * @tx_pkt length.
	 */
	uint16_t			tx_pkt_len;

	/*
	 * Receive buffer.
	 */
	struct pkt			rx_pkt;

	/*
	 * Transmit (send) buffer.
	 */
	struct pkt			tx_pkt;

	/*
	 * Total received bytes.
	 */
	uint64_t			rx_total;

	/*
	 * Total transmitted bytes.
	 */
	uint64_t			tx_total;

	/*
	 * Client username.
	 */
	char				username[256];

	/*
	 * Loop counter. To avoid too many sync requests.
	 */
	uint8_t				loop_counter;

	/*
	 * The indicator whether the client is authenticated or not.
	 */
	bool				is_authenticated;

	/*
	 * UDP is stateless, therefore we have to keep track
	 * of the last activity of the client. When the client
	 * is not doing anything in a certain period of time,
	 * we assume that the client is disconnected.
	 */
	struct timespec			last_act;
};

/*
 * Server UDP context.
 */
struct srv_udp_ctx {
	/*
	 * Server UDP socket file descriptor.
	 */
	int			udp_fd;

	/*
	 * Server epoll file descriptor.
	 */
	int			epl_fd;

	/*
	 * Session free slot tracking.
	 */
	struct free_slot	sess_slot;

	/*
	 * Session array.
	 */
	struct udp_sess		*sessions;

	/*
	 * Server configuration.
	 */
	struct srv_cfg		*cfg;
};

extern int run_server_app(struct srv_cfg *cfg);
extern int run_server_udp(struct srv_cfg *cfg);
extern int run_server_udp_epoll(struct srv_udp_ctx *ctx);
extern int init_server_udp_sessions(struct udp_sess **sessions_p, uint16_t n);
extern void destroy_server_udp_sessions(struct udp_sess *sessions);

#endif /* #ifndef TEAVPN2__AP__LINUX__SERVER_H */
