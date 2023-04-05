// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2023  Ammar Faizi <ammarfaizi2@gnuweeb.org>
 */

#include <teavpn2/common.h>
#include <teavpn2/server.h>
#include <teavpn2/helpers.h>
#include <teavpn2/ap/linux/server.h>

int run_server_app(struct srv_cfg *cfg)
{
	switch (cfg->sock.type) {
	case SOCK_TYPE_UDP:
		return run_server_udp(cfg);
		break;
	case SOCK_TYPE_TCP:
	default:
		return -EPROTONOSUPPORT;
	}
}

/*
 * Taken from gwrok.
 *
 * Link: https://github.com/alviroiskandar/gwrok/blob/a9468ff3e746ca91d3158c3cafdcb5b913f2b4cf/gwrok.c#L1154-L1180
 */
__cold int init_server_free_slot(struct free_slot *slot, uint16_t n)
{
	struct stack32 *stack;
	uint32_t i;
	int ret;

	stack = malloc(sizeof(*stack) + sizeof(stack->arr[0]) * n);
	if (!stack)
		return -ENOMEM;

	ret = mutex_init(&slot->lock);
	if (ret) {
		free(stack);
		return -ret;
	}

	i = n;
	stack->rsp = n;
	stack->rbp = n;

	/* Whee... */
	while (i--)
		stack->arr[--stack->rsp] = i;

	slot->stack = stack;
	return 0;
}
