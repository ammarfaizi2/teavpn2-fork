// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2023  Ammar Faizi <ammarfaizi2@gnuweeb.org>
 */

#ifndef TEAVPN2__COMPILER_ATTR_H
#define TEAVPN2__COMPILER_ATTR_H

#ifndef __printf
#define __printf(a, b)	__attribute__((__format__(printf, a, b)))
#endif

#ifndef __packed
#define __packed	__attribute__((__packed__))
#endif

#ifndef __aligned
#define __aligned(x)	__attribute__((__aligned__(x)))
#endif

#ifndef __unused
#define __unused	__attribute__((__unused__))
#endif

#ifndef __maybe_unused
#define __maybe_unused	__attribute__((__unused__))
#endif

#ifndef __cold
#define __cold		__attribute__((__cold__))
#endif

#ifndef __hot
#define __hot		__attribute__((__hot__))
#endif

#ifndef __always_inline
#define __always_inline	inline __attribute__((__always_inline__))
#endif

#ifndef __noinline
#define __noinline	__attribute__((__noinline__))
#endif

#ifndef __noreturn
#define __noreturn	__attribute__((__noreturn__))
#endif

#ifndef __malloc
#define __malloc	__attribute__((__malloc__))
#endif

#ifndef __must_check
#define __must_check	__attribute__((__warn_unused_result__))
#endif

#ifndef __used
#define __used		__attribute__((__used__))
#endif

#ifndef ____stringify
#define ____stringify(EXPR) #EXPR
#endif

#ifndef __stringify
#define __stringify(EXPR) ____stringify(EXPR)
#endif

#ifndef likely
#define likely(x)	__builtin_expect(!!(x), 1)
#endif

#ifndef unlikely
#define unlikely(x)	__builtin_expect(!!(x), 0)
#endif

#ifndef ARRAY_SIZE
#define ARRAY_SIZE(x)	(sizeof(x) / sizeof((x)[0]))
#endif

#ifdef __CHECKER__
#define __must_hold(x)		__attribute__((context(x,1,1)))
#define __acquires(x)		__attribute__((context(x,0,1)))
#define __cond_acquires(x)	__attribute__((context(x,0,-1)))
#define __releases(x)		__attribute__((context(x,1,0)))
#define __acquire(x)		__context__(x,1)
#define __release(x)		__context__(x,-1)
#define __cond_lock(x,c)	((c) ? ({ __acquire(x); 1; }) : 0)
#else /* #ifdef __CHECKER__ */
#define __must_hold(x)
#define __acquires(x)
#define __cond_acquires(x)
#define __releases(x)
#define __acquire(x)		(void)0
#define __release(x)		(void)0
#define __cond_lock(x,c)	(c)
#endif /* #ifdef __CHECKER__ */

#endif /* #ifndef TEAVPN2__COMPILER_ATTR_H */
