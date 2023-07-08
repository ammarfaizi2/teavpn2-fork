// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2023  Ammar Faizi <ammarfaizi2@gnuweeb.org>
 */

#ifndef TEAVPN2__ARCH__X86__LINUX_SYSCALL_H
#define TEAVPN2__ARCH__X86__LINUX_SYSCALL_H

#define __do_syscall0(N) ({			\
	long __rax = (N);			\
						\
	__asm__ volatile (			\
		"syscall"			\
		: "+a" (__rax)  /* %rax */	\
		:				\
		: "memory", "rcx", "r11"	\
	);					\
	(__rax);				\
})

#define __do_syscall1(N, A) ({			\
	long __rax = (N);			\
						\
	__asm__ volatile (			\
		"syscall"			\
		: "+a" (__rax)  /* %rax */	\
		: "D" (A)       /* %rdi */	\
		: "memory", "rcx", "r11"	\
	);					\
	(__rax);				\
})

#define __do_syscall2(N, A, B) ({		\
	long __rax = (N);			\
						\
	__asm__ volatile (			\
		"syscall"			\
		: "+a" (__rax)	/* %rax */	\
		: "D" (A),      /* %rdi */	\
		  "S" (B)       /* %rsi */	\
		: "memory", "rcx", "r11"	\
	);					\
	(__rax);				\
})

#define __do_syscall3(N, A, B, C) ({		\
	long __rax = (N);			\
						\
	__asm__ volatile (			\
		"syscall"			\
		: "+a" (__rax)	/* %rax */	\
		: "D" (A),      /* %rdi */	\
		  "S" (B),      /* %rsi */	\
		  "d" (C)       /* %rdx */	\
		: "memory", "rcx", "r11"	\
	);					\
	(__rax);				\
})

#define __do_syscall4(N, A, B, C, D) ({				\
	long __rax = (N);					\
	register __typeof__(D) __r10 __asm__("r10") = (D);	\
								\
	__asm__ volatile (					\
		"syscall"					\
		: "+a" (__rax)	/* %rax */			\
		: "D" (A),      /* %rdi */			\
		  "S" (B),      /* %rsi */			\
		  "d" (C),      /* %rdx */			\
		  "r" (__r10)   /* %r10 */			\
		: "memory", "rcx", "r11"			\
	);							\
	(__rax);						\
})

#define __do_syscall5(N, A, B, C, D, E) ({			\
	long __rax = (N);					\
	register __typeof__(D) __r10 __asm__("r10") = (D);	\
	register __typeof__(E) __r8  __asm__("r8")  = (E);	\
								\
	__asm__ volatile (					\
		"syscall"					\
		: "+a" (__rax)	/* %rax */			\
		: "D" (A),      /* %rdi */			\
		  "S" (B),      /* %rsi */			\
		  "d" (C),      /* %rdx */			\
		  "r" (__r10),  /* %r10 */			\
		  "r" (__r8)    /* %r8 */			\
		: "memory", "rcx", "r11"			\
	);							\
	(__rax);						\
})

#define __do_syscall6(N, A, B, C, D, E, F) ({			\
	long __rax = (N);					\
	register __typeof__(D) __r10 __asm__("r10") = (D);	\
	register __typeof__(E) __r8  __asm__("r8")  = (E);	\
	register __typeof__(F) __r9  __asm__("r9")  = (F);	\
								\
	__asm__ volatile (					\
		"syscall"					\
		: "+a" (__rax)	/* %rax */			\
		: "D" (A),      /* %rdi */			\
		  "S" (B),      /* %rsi */			\
		  "d" (C),      /* %rdx */			\
		  "r" (__r10),  /* %r10 */			\
		  "r" (__r8),   /* %r8 */			\
		  "r" (__r9)    /* %r9 */			\
		: "memory", "rcx", "r11"			\
	);							\
	(__rax);						\
})

#endif /* #ifndef TEAVPN2__ARCH__X86__LINUX_SYSCALL_H */
