// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2023  Ammar Faizi <ammarfaizi2@gnuweeb.org>
 * Copyright (C) 2023  Alviro Iskandar Setiawan <alviro.iskandar@gnuweeb.org>
 */

#ifndef TEAVPN2__SERVER__HELPERS_H
#define TEAVPN2__SERVER__HELPERS_H

#include <teavpn2/helpers.h>

struct stack16 {
	uint16_t	rbp;
	uint16_t	rsp;
	uint16_t	arr[];
};

struct free_slot {
	mutex_t		lock;
	struct stack16	*stack;
};

/*
 * Taken from gwrok.
 *
 * Link: https://github.com/alviroiskandar/gwrok/blob/a9468ff3e746ca91d3158c3cafdcb5b913f2b4cf/gwrok.c#L1154-L1180
 */
extern int init_free_slot(struct free_slot *slot, uint32_t n);
extern int64_t __push_free_slot(struct free_slot *fs, uint32_t data);
extern int64_t push_free_slot(struct free_slot *fs, uint32_t data);
extern int64_t __pop_free_slot(struct free_slot *fs);
extern int64_t pop_free_slot(struct free_slot *fs);
extern void destroy_free_slot(struct free_slot *fs);

#endif /* #ifndef TEAVPN2__SERVER__HELPERS_H */
