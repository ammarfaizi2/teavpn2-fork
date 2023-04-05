// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2023  Ammar Faizi <ammarfaizi2@gnuweeb.org>
 * Copyright (C) 2023  Alviro Iskandar Setiawan <alviro.iskandar@gnuweeb.org>
 */

#include <teavpn2/common.h>
#include <teavpn2/server.h>
#include <teavpn2/helpers.h>
#include <teavpn2/ap/linux/server.h>
#include <unistd.h>

enum {
	EVT_EPOLL = 0,
	EVT_IO_URING = 1
};

__cold static int select_server_event_loop(struct srv_cfg *cfg)
{
	const char *ev = cfg->sock.event_loop;

	if (!strcmp(ev, "epoll")) {
		return EVT_EPOLL;
	} else if (!strcmp(ev, "io_uring")) {
		fprintf(stderr, "event_loop=io_uring is not supported yet\n");
		return -EOPNOTSUPP;
	}

	fprintf(stderr, "Invalid event loop: %s (enum values: epoll, io_uring)\n", ev);
	return -EINVAL;
}

__cold static int init_server_udp_socket(struct srv_udp_ctx *ctx)
{
	struct srv_cfg_sock *sock = &ctx->cfg->sock;
	struct sockaddr_storage addr;
	int ret;
	int fd;

	memset(&addr, 0, sizeof(addr));
	ret = str_to_sockaddr(&addr, sock->bind_addr, sock->bind_port);
	if (ret < 0) {
		fprintf(stderr, "Invalid bind address: %s:%hu\n",
			sock->bind_addr, sock->bind_port);
		return ret;
	}

	fd = socket(addr.ss_family, SOCK_DGRAM, IPPROTO_UDP);
	if (fd < 0) {
		ret = -errno;
		perror("socket");
		return ret;
	}

	ret = bind(fd, (struct sockaddr *)&addr, sizeof(addr));
	if (ret < 0) {
		ret = -errno;
		close(fd);
		perror("bind");
		return ret;
	}

	ctx->udp_fd = fd;
	return 0;
}

__cold static void destroy_server_udp_socket(struct srv_udp_ctx *ctx)
{
	if (ctx->udp_fd >= 0)
		close(ctx->udp_fd);

	if (ctx->sessions)
		destroy_server_udp_sessions(ctx->sessions);
}

__cold static int init_server_udp_context(struct srv_udp_ctx *ctx)
{
	uint16_t max_conn = ctx->cfg->sock.max_conn;
	int ret;

	ret = init_server_udp_socket(ctx);
	if (ret < 0)
		return ret;
	ret = init_server_free_slot(&ctx->sess_slot, max_conn);
	if (ret < 0)
		goto out_err;
	ret = init_server_udp_sessions(&ctx->sessions, max_conn);
	if (ret < 0)
		goto out_err;

	return 0;

out_err:
	destroy_server_udp_socket(ctx);
	return ret;
}

int run_server_udp(struct srv_cfg *cfg)
{
	struct srv_udp_ctx ctx;
	int ret, ev;

	ev = select_server_event_loop(cfg);
	if (ev < 0)
		return ev;

	memset(&ctx, 0, sizeof(ctx));
	ctx.udp_fd = -1;
	ctx.epl_fd = -1;

	ctx.cfg = cfg;
	ret = init_server_udp_context(&ctx);
	if (ret < 0)
		return ret;

	return ret;
}
