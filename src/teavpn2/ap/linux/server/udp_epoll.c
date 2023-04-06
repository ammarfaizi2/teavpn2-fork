// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2023  Ammar Faizi <ammarfaizi2@gnuweeb.org>
 * Copyright (C) 2023  Alviro Iskandar Setiawan <alviro.iskandar@gnuweeb.org>
 */

#include <teavpn2/common.h>
#include <teavpn2/server.h>
#include <teavpn2/helpers.h>
#include <teavpn2/ap/linux/server.h>
#include <sys/epoll.h>
#include <unistd.h>

__cold static int init_server_udp_epoll(struct srv_udp_ctx *ctx)
{
	int ret;

	ret = __sys_epoll_create(ctx->cfg->sock.max_conn);
	if (ret < 0) {
		pr_err("epoll_create(): " PRERF, PREAR(-ret));
		return ret;
	}

	ctx->epl_fd = ret;
	return 0;
}

__hot static int epoll_add(int epl_fd, int fd, uint32_t events,
			   union epoll_data data)
{
	struct epoll_event ev = {
		.events = events,
		.data = data
	};
	int ret;

	ret = __sys_epoll_ctl(epl_fd, EPOLL_CTL_ADD, fd, &ev);
	if (unlikely(ret < 0)) {
		pr_err("epoll_ctl(%d, EPOLL_CTL_ADD, %d): " PRERF, epl_fd, fd,
		       PREAR(-ret));
		return ret;
	}

	return 0;
}

__hot static int epoll_del(int epl_fd, int fd)
{
	int ret;

	ret = __sys_epoll_ctl(epl_fd, EPOLL_CTL_DEL, fd, NULL);
	if (unlikely(ret < 0)) {
		pr_err("epoll_ctl(%d, EPOLL_CTL_DEL, %d): " PRERF, epl_fd, fd,
		       PREAR(-ret));
		return ret;
	}

	return 0;
}

static void destroy_server_udp_epoll(struct srv_udp_ctx *ctx)
{
	__sys_close(ctx->epl_fd);
}

int run_server_udp_epoll(struct srv_udp_ctx *ctx)
{
	int ret;

	ret = init_server_udp_epoll(ctx);
	if (ret)
		return ret;

	destroy_server_udp_epoll(ctx);
	return 0;
}
