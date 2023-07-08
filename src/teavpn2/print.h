// SPDX-License-Identifier: GPL-2.0-only
/*
 *  Printing header
 *
 *  Copyright (C) 2021  Ammar Faizi
 */

#ifndef TEAVPN2__PRINT_H
#define TEAVPN2__PRINT_H

#include <stdarg.h>
#include <teavpn2/common.h>

/**
 * 0: Silent (only print panic message)
 * 1: Emergency
 * 2: Emergency, Error
 * 3: Emergency, Error, Warning
 * 4: Emergency, Error, Warning, Info
 * 5: Emergency, Error, Warning, Info, Debug
 * >= 6: same as 5
 */
extern uint8_t __log_level;

enum {
	__LOG_EMERG	= 1,
	__LOG_ERROR	= 2,
	__LOG_WARN	= 3,
	__LOG_INFO	= 4,
	__LOG_DEBUG	= 5,
};

extern void set_log_level(uint8_t level);
extern void __printf(3, 4) __noreturn
__panic(const char *file, int lineno, const char *fmt, ...);

#ifdef CONFIG_LOG_FILE_AND_LINE
extern void __printf(4, 5)
__pr_log(uint8_t level, const char *file, int lineno, const char *fmt, ...);

#define pr_log(level, ...) 						\
do {									\
	uint8_t ____level = (level);					\
	if (____level <= __log_level) {					\
		__pr_log(____level, __FILE__, __LINE__, __VA_ARGS__);	\
	}								\
} while (0)
#else /* #ifdef CONFIG_LOG_FILE_AND_LINE */
extern void __printf(2, 3) __pr_log(uint8_t level, const char *fmt, ...);

#define pr_log(level, ...) 						\
do {									\
	uint8_t ____level = (level);					\
	if (____level <= __log_level) {					\
		__pr_log(____level, __VA_ARGS__);			\
	}								\
} while (0)
#endif /* #ifdef CONFIG_LOG_FILE_AND_LINE */

#define pr_emerg(...) pr_log(__LOG_EMERG, __VA_ARGS__)
#define pr_error(...) pr_log(__LOG_ERROR, __VA_ARGS__)
#define pr_warn(...) pr_log(__LOG_WARN, __VA_ARGS__)
#define pr_info(...) pr_log(__LOG_INFO, __VA_ARGS__)
#define pr_debug(...) pr_log(__LOG_DEBUG, __VA_ARGS__)
#define pr_err(...) pr_error(__VA_ARGS__)
#define pr_dbg(...) pr_debug(__VA_ARGS__)

#endif /* #ifndef TEAVPN2__PRINT_H */
