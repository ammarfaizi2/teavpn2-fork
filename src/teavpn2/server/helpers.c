// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2023  Ammar Faizi <ammarfaizi2@gnuweeb.org>
 * Copyright (C) 2023  Alviro Iskandar Setiawan <alviro.iskandar@gnuweeb.org>
 */

#include <teavpn2/common.h>
#include <teavpn2/server/helpers.h>

/*
 * Taken from gwrok.
 *
 * Link: https://github.com/alviroiskandar/gwrok/blob/a9468ff3e746ca91d3158c3cafdcb5b913f2b4cf/gwrok.c#L1154-L1180
 */
__cold int init_free_slot(struct free_slot *slot, uint32_t n)
{
	struct stack16 *stack;
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

__hot int64_t __push_free_slot(struct free_slot *fs, uint32_t data)
{
	struct stack16 *stack = fs->stack;
	int64_t ret;

	if (stack->rsp == 0) {
		ret = -EAGAIN;
	} else {
		stack->arr[--stack->rsp] = data;
		ret = 0;
	}

	return ret;
}

__hot int64_t __pop_free_slot(struct free_slot *fs)
{
	struct stack16 *stack = fs->stack;
	int64_t ret;

	if (stack->rsp == stack->rbp)
		ret = -EAGAIN;
	else
		ret = stack->arr[stack->rsp++];

	return ret;
}

__hot int64_t push_free_slot(struct free_slot *fs, uint32_t data)
{
	int64_t ret;

	mutex_lock(&fs->lock);
	ret = __push_free_slot(fs, data);
	mutex_unlock(&fs->lock);
	return ret;
}

__hot int64_t pop_free_slot(struct free_slot *fs)
{
	int64_t ret;

	mutex_lock(&fs->lock);
	ret = __pop_free_slot(fs);
	mutex_unlock(&fs->lock);
	return ret;
}

__cold void destroy_free_slot(struct free_slot *fs)
{
	if (!fs->stack)
		return;

	mutex_destroy(&fs->lock);
	free(fs->stack);
	memset(fs, 0, sizeof(*fs));
}
