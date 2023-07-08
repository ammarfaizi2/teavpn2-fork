// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2023  Ammar Faizi <ammarfaizi2@gnuweeb.org>
 */

#ifndef TEAVPN2__ARCH__LINUX_SYSCALL_H
#define TEAVPN2__ARCH__LINUX_SYSCALL_H

#if defined(__x86_64__) || defined(__i386__)
#include <teavpn2/arch/x86/linux_syscall.h>
#elif defined(__aarch64__)
#include <teavpn2/arch/aarch64/linux_syscall.h>
#else
#include <teavpn2/arch/generic/linux_syscall.h>
#endif

#include <sys/syscall.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/epoll.h>
#include <unistd.h>
#include <fcntl.h>
#include <poll.h>

static inline int __sys_open(const char *pathname, int flags, mode_t mode)
{
#ifdef __NR_open
	return (int)__do_syscall3(__NR_open, pathname, flags, mode);
#else
	return (int)__do_syscall3(__NR_openat, AT_FDCWD, pathname, flags, mode);
#endif
}

static inline int __sys_socket(int domain, int type, int protocol)
{
	return (int)__do_syscall3(__NR_socket, domain, type, protocol);
}

static inline int __sys_bind(int sockfd, const struct sockaddr *addr,
			     socklen_t addrlen)
{
	return (int)__do_syscall3(__NR_bind, sockfd, addr, addrlen);
}

static inline int __sys_listen(int sockfd, int backlog)
{
	return (int)__do_syscall2(__NR_listen, sockfd, backlog);
}

static inline int __sys_accept4(int sockfd, struct sockaddr *addr,
				socklen_t *addrlen, int flags)
{
	return (int)__do_syscall4(__NR_accept4, sockfd, addr, addrlen, flags);
}

static inline int __sys_accept(int sockfd, struct sockaddr *addr,
			       socklen_t *addrlen)
{
	return __sys_accept4(sockfd, addr, addrlen, 0);
}

static inline int __sys_connect(int sockfd, const struct sockaddr *addr,
				socklen_t addrlen)
{
	return (int)__do_syscall3(__NR_connect, sockfd, addr, addrlen);
}

static inline int __sys_setsockopt(int sockfd, int level, int optname,
				   const void *optval, socklen_t optlen)
{
	return (int)__do_syscall5(__NR_setsockopt, sockfd, level, optname,
				  optval, optlen);
}

static inline int __sys_getsockopt(int sockfd, int level, int optname,
				   void *optval, socklen_t *optlen)
{
	return (int)__do_syscall5(__NR_getsockopt, sockfd, level, optname,
				  optval, optlen);
}

static inline int __sys_getsockname(int sockfd, struct sockaddr *addr,
				    socklen_t *addrlen)
{
	return (int)__do_syscall3(__NR_getsockname, sockfd, addr, addrlen);
}

static inline int __sys_getpeername(int sockfd, struct sockaddr *addr,
				    socklen_t *addrlen)
{
	return (int)__do_syscall3(__NR_getpeername, sockfd, addr, addrlen);
}

static inline int __sys_shutdown(int sockfd, int how)
{
	return (int)__do_syscall2(__NR_shutdown, sockfd, how);
}

static inline int __sys_close(int fd)
{
	return (int)__do_syscall1(__NR_close, fd);
}

static inline ssize_t __sys_read(int fd, void *buf, size_t count)
{
	return (ssize_t)__do_syscall3(__NR_read, fd, buf, count);
}

static inline ssize_t __sys_write(int fd, const void *buf, size_t count)
{
	return (ssize_t)__do_syscall3(__NR_write, fd, buf, count);
}

static inline ssize_t __sys_sendto(int sockfd, const void *buf, size_t len,
				   int flags, const struct sockaddr *dest_addr,
				   socklen_t addrlen)
{
	return (ssize_t)__do_syscall6(__NR_sendto, sockfd, buf, len, flags,
				      dest_addr, addrlen);
}

static inline ssize_t __sys_recvfrom(int sockfd, void *buf, size_t len,
				     int flags, struct sockaddr *src_addr,
				     socklen_t *addrlen)
{
	return (ssize_t)__do_syscall6(__NR_recvfrom, sockfd, buf, len, flags,
				      src_addr, addrlen);
}

static inline ssize_t __sys_send(int sockfd, const void *buf, size_t len,
				 int flags)
{
	return __sys_sendto(sockfd, buf, len, flags, NULL, 0);
}

static inline ssize_t __sys_recv(int sockfd, void *buf, size_t len, int flags)
{
	return __sys_recvfrom(sockfd, buf, len, flags, NULL, NULL);
}

static inline int __sys_sendmsg(int sockfd, const struct msghdr *msg,
				int flags)
{
	return (int)__do_syscall3(__NR_sendmsg, sockfd, msg, flags);
}

static inline int __sys_recvmsg(int sockfd, struct msghdr *msg, int flags)
{
	return (int)__do_syscall3(__NR_recvmsg, sockfd, msg, flags);
}

static inline int __sys_fcntl(int fd, int cmd, long arg)
{
	return (int)__do_syscall3(__NR_fcntl, fd, cmd, arg);
}

static inline int __sys_fcntl_getfl(int fd)
{
	return __sys_fcntl(fd, F_GETFL, 0);
}

static inline int __sys_fcntl_setfl(int fd, int flags)
{
	return __sys_fcntl(fd, F_SETFL, flags);
}

static inline int __sys_epoll_create(int n)
{
	return (int)__do_syscall1(__NR_epoll_create, n);
}

static inline int __sys_epoll_create1(int flags)
{
	return (int)__do_syscall1(__NR_epoll_create1, flags);
}

static inline int __sys_epoll_ctl(int epfd, int op, int fd,
				  struct epoll_event *event)
{
	return (int)__do_syscall4(__NR_epoll_ctl, epfd, op, fd, event);
}

static inline int __sys_epoll_wait(int epfd, struct epoll_event *events,
				   int maxevents, int timeout)
{
	return (int)__do_syscall4(__NR_epoll_wait, epfd, events, maxevents,
				  timeout);
}

static inline int __sys_epoll_pwait(int epfd, struct epoll_event *events,
				    int maxevents, int timeout,
				    const sigset_t *sigmask)
{
	return (int)__do_syscall5(__NR_epoll_pwait, epfd, events, maxevents,
				  timeout, sigmask);
}

static inline int __sys_poll(struct pollfd *fds, nfds_t nfds, int timeout)
{
	return (int)__do_syscall3(__NR_poll, fds, nfds, timeout);
}

static inline int __sys_ppoll(struct pollfd *fds, nfds_t nfds,
			      const struct timespec *timeout,
			      const sigset_t *sigmask)
{
	return (int)__do_syscall4(__NR_ppoll, fds, nfds, timeout, sigmask);
}

#endif /* #ifndef TEAVPN2__ARCH__LINUX_SYSCALL_H */
