// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2023  Ammar Faizi <ammarfaizi2@gnuweeb.org>
 */

#ifndef TEAVPN2__COMMON_H
#define TEAVPN2__COMMON_H

#include <stdio.h>
#include <errno.h>
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <stdarg.h>
#include <assert.h>
#include <stdbool.h>
#include <teavpn2/compiler_attr.h>

#ifndef STR
#define STR(a) #a
#endif

#ifndef XSTR
#define XSTR(a) STR(a)
#endif

#define TEAVPN2_VERSION \
	XSTR(VERSION) "." XSTR(PATCHLEVEL) "." XSTR(SUBLEVEL) EXTRAVERSION

#ifndef SIZE_ASSERT
#define SIZE_ASSERT(TYPE, LEN) 						\
	static_assert(sizeof(TYPE) == (LEN),				\
		      "Bad " __stringify(sizeof(TYPE) == (LEN)))
#endif

#ifndef OFFSET_ASSERT
#define OFFSET_ASSERT(TYPE, EQU, MEM) 					\
	static_assert(offsetof(TYPE, MEM) == (EQU),			\
		      "Bad " __stringify(offsetof(TYPE, MEM) == (EQU)))
#endif

/*
 * The size of this struct matters, because it will be sent
 * over the network.
 */
struct teavpn2_version {
	uint8_t	ver;
	uint8_t	patch_lvl;
	uint8_t	sub_lvl;
	char	extra[29];
};
OFFSET_ASSERT(struct teavpn2_version, 0, ver);
OFFSET_ASSERT(struct teavpn2_version, 1, patch_lvl);
OFFSET_ASSERT(struct teavpn2_version, 2, sub_lvl);
OFFSET_ASSERT(struct teavpn2_version, 3, extra);
SIZE_ASSERT(struct teavpn2_version, 32);

void show_version(void);
#ifdef CONFIG_TEAVPN_SERVER
extern int run_server(int argc, char *argv[]);
#else /* #ifdef CONFIG_TEAVPN_SERVER */
static inline int run_server(int argc, char *argv[])
{
	(void)argc;
	(void)argv;
	printf("Server mode is not suported in this build.\n");
	return -ENOTSUP;
}
#endif /* #ifdef CONFIG_TEAVPN_SERVER */

#ifdef CONFIG_TEAVPN_CLIENT
extern int run_client(int argc, char *argv[]);
#else /* #ifdef CONFIG_TEAVPN_CLIENT */
static inline int run_client(int argc, char *argv[])
{
	(void)argc;
	(void)argv;
	printf("Client mode is not supported in this build.\n");
	return -ENOTSUP;
}
#endif /* #ifdef CONFIG_TEAVPN_CLIENT */

#include <teavpn2/print.h>

#endif /* #ifndef TEAVPN2__COMMON_H */
