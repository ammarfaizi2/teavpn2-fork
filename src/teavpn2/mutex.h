// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2021  Ammar Faizi
 */
#ifndef TEAVPN2__MUTEX_H
#define TEAVPN2__MUTEX_H

#include <stdint.h>
#include <stdlib.h>
#include <pthread.h>
#include <stdatomic.h>
#include <teavpn2/common.h>

#define __MUTEX_LEAK_ASSERT 1
#ifndef __MUTEX_LEAK_ASSERT
#define __MUTEX_LEAK_ASSERT 0
#endif


struct tmutex {
	pthread_mutex_t			mutex;

#if __MUTEX_LEAK_ASSERT
	union {
		void			*__leak_assert;
		uintptr_t		need_destroy;
	};
	_Atomic(bool)			lock_is_held;
#else
	bool				need_destroy;
#endif
};


#define MUTEX_INITIALIZER			\
{						\
	.mutex = PTHREAD_MUTEX_INITIALIZER	\
}

#define DEFINE_MUTEX(V) struct tmutex V = MUTEX_INITIALIZER

#if __MUTEX_LEAK_ASSERT
#define lockdep_assert_held(m)				\
	do {						\
		BUG_ON(!atomic_load(&m->lock_is_held));	\
	} while (0)
#else
#define lockdep_assert_held(m) do { } while (0)
#endif

static __always_inline int mutex_init(struct tmutex *m,
				      const pthread_mutexattr_t *attr)
{
	int ret;

	ret = pthread_mutex_init(&m->mutex, attr);
	if (unlikely(ret)) {
		pr_err("pthread_mutex_init(): " PRERF, PREAR(ret));
		return -ret;
	}

#if __MUTEX_LEAK_ASSERT
	m->__leak_assert = malloc(1);
	BUG_ON(!m->__leak_assert);
	atomic_store(&m->lock_is_held, true);
#else
	m->need_destroy = true;
#endif

	return ret;
}

static __always_inline int mutex_lock(struct tmutex *m)
{
	int ret = pthread_mutex_lock(&m->mutex);
#if __MUTEX_LEAK_ASSERT
	atomic_store(&m->lock_is_held, true);
#endif
	return ret;
}

static __always_inline int mutex_unlock(struct tmutex *m)
{
	int ret = pthread_mutex_unlock(&m->mutex);
#if __MUTEX_LEAK_ASSERT
	atomic_store(&m->lock_is_held, false);
#endif
	return ret;
}

static __always_inline int mutex_trylock(struct tmutex *m)
{
	int ret = pthread_mutex_trylock(&m->mutex);
#if __MUTEX_LEAK_ASSERT
	if (!ret)
		atomic_store(&m->lock_is_held, true);
#endif
	return ret;
}

static __always_inline int mutex_destroy(struct tmutex *m)
{
	BUG_ON(!m->need_destroy);

#if __MUTEX_LEAK_ASSERT
	free(m->__leak_assert);
#endif

	return pthread_mutex_destroy(&m->mutex);
}

#endif /* #ifndef TEAVPN2__MUTEX_H */
