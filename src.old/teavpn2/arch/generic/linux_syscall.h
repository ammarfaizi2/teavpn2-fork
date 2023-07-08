// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2023  Ammar Faizi <ammarfaizi2@gnuweeb.org>
 */

#ifndef TEAVPN2__ARCH__GENERIC__LINUX_SYSCALL_H
#define TEAVPN2__ARCH__GENERIC__LINUX_SYSCALL_H

#include <sys/syscall.h>
#include <errno.h>

#define __do_syscall0(N) ({			\
	long __ret;				\
						\
	__ret = syscall(N);			\
	(long)((__ret == -1) ? -errno : __ret)	\
})

#define __do_syscall1(N, A) ({			\
	long __ret;				\
						\
	__ret = syscall(N, A);			\
	(long)((__ret == -1) ? -errno : __ret)	\
})

#define __do_syscall2(N, A, B) ({		\
	long __ret;				\
						\
	__ret = syscall(N, A, B);		\
	(long)((__ret == -1) ? -errno : __ret)	\
})

#define __do_syscall3(N, A, B, C) ({		\
	long __ret;				\
						\
	__ret = syscall(N, A, B, C);		\
	(long)((__ret == -1) ? -errno : __ret)	\
})

#define __do_syscall4(N, A, B, C, D) ({		\
	long __ret;				\
						\
	__ret = syscall(N, A, B, C, D);		\
	(long)((__ret == -1) ? -errno : __ret)	\
})

#define __do_syscall5(N, A, B, C, D, E) ({	\
	long __ret;				\
						\
	__ret = syscall(N, A, B, C, D, E);	\
	(long)((__ret == -1) ? -errno : __ret)	\
})

#define __do_syscall6(N, A, B, C, D, E, F) ({	\
	long __ret;				\
						\
	__ret = syscall(N, A, B, C, D, E, F);	\
	(long)((__ret == -1) ? -errno : __ret)	\
})

#endif /* #ifndef TEAVPN2__ARCH__GENERIC__LINUX_SYSCALL_H */
