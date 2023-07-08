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
		pr_notice("Using epoll as event loop");
		return EVT_EPOLL;
	} else if (!strcmp(ev, "io_uring")) {
		pr_err("event_loop=io_uring is not supported yet");
		return -EOPNOTSUPP;
	}

	pr_err("Invalid event loop: %s (valid values: epoll, io_uring)", ev);
	return -EINVAL;
}

__cold static int init_server_udp_socket(struct srv_udp_ctx *ctx, int ev)
{
	struct srv_cfg_sock *sock = &ctx->cfg->sock;
	struct sockaddr_storage addr;
	int type = SOCK_DGRAM;
	int ret;
	int fd;

	memset(&addr, 0, sizeof(addr));
	ret = str_to_sockaddr(&addr, sock->bind_addr, sock->bind_port);
	if (ret < 0) {
		pr_err("str_to_sockaddr(%s:%hu): " PRERF, sock->bind_addr,
		       sock->bind_port, PREAR(-ret));
		return ret;
	}

	if (ev == EVT_EPOLL)
		type |= SOCK_NONBLOCK;

	fd = __sys_socket(addr.ss_family, type, IPPROTO_UDP);
	if (fd < 0) {
		pr_err("socket(): " PRERF, PREAR(-ret));
		return ret;
	}

	ret = __sys_bind(fd, (struct sockaddr *)&addr, sizeof(addr));
	if (ret < 0) {
		__sys_close(fd);
		pr_err("bind(%s:%hu) " PRERF, sock->bind_addr, sock->bind_port,
		       PREAR(-ret));
		return ret;
	}

	ctx->udp_fd = fd;
	return 0;
}

__cold static void destroy_server_udp_socket(struct srv_udp_ctx *ctx)
{
	if (ctx->udp_fd >= 0)
		__sys_close(ctx->udp_fd);

	if (ctx->sessions)
		destroy_server_udp_sessions(ctx->sessions);
}

__cold static int __run_server_udp(struct srv_udp_ctx *ctx, int ev)
{
	uint16_t max_conn = ctx->cfg->sock.max_conn;
	int ret;

	ret = init_server_udp_socket(ctx, ev);
	if (ret < 0)
		return ret;

	ret = init_free_slot(&ctx->sess_slot, max_conn);
	if (ret < 0)
		goto out;

	ret = init_server_udp_sessions(&ctx->sessions, max_conn);
	if (ret < 0)
		goto out;

	switch (ev) {
	case EVT_EPOLL:
		ret = run_server_udp_epoll(ctx);
		break;
	case EVT_IO_URING:
		ret = -EOPNOTSUPP;
		break;
	}

out:
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
	ret = __run_server_udp(&ctx, ev);
	if (ret < 0)
		return ret;

	return ret;
}
