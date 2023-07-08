// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2023  Ammar Faizi <ammarfaizi2@gnuweeb.org>
 */

#include <teavpn2/server.h>

static int server_init_tcp_socket(struct srv_ctx *ctx)
{
	return 0;
}

static int server_init_ctx(struct srv_ctx *ctx)
{

	return 0;
}

int run_server_app(struct srv_cfg *cfg)
{
	struct srv_ctx_tcp ctx;
	int ret;

	memset(&ctx, 0, sizeof(ctx));
	ctx.cfg = cfg;

	ret = server_init_ctx(&ctx);
	if (ret < 0)
		return ret;

	return ret;
}
