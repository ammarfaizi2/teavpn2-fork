// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2023  Ammar Faizi <ammarfaizi2@gnuweeb.org>
 * Copyright (C) 2023  Alviro Iskandar Setiawan <alviro.iskandar@gnuweeb.org>
 */

#include <teavpn2/linux/mutex.h>
#include <teavpn2/common.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>

int mutex_init(mutex_t *m)
{
	int ret;

	ret = pthread_mutex_init(&m->mutex, NULL);
	if (ret)
		return -ret;

#ifdef CONFIG_DEBUG_MUTEX
	atomic_store(&m->locked, false);
	m->leak_assert = malloc(1);
	if (!m->leak_assert) {
		pthread_mutex_destroy(&m->mutex);
		return ENOMEM;
	}
#endif
	return 0;
}

int mutex_destroy(mutex_t *m)
{
#ifdef CONFIG_DEBUG_MUTEX
	if (atomic_load(&m->locked)) {
		fprintf(stderr, "mutex_destroy: mutex is still locked!\n");
		abort();
	}
	free(m->leak_assert);
#endif
	return pthread_mutex_destroy(&m->mutex);
}

int mutex_lock(mutex_t *m)
	__acquires(m)
{
	int ret;

	ret = pthread_mutex_lock(&m->mutex);

#ifdef CONFIG_DEBUG_MUTEX
	if (likely(!ret)) {
		if (unlikely(atomic_load(&m->locked))) {
			fprintf(stderr, "mutex_lock: mutex is already locked!\n");
			abort();
		}
		atomic_store(&m->locked, true);
	}
#endif
	return ret;
}

int mutex_unlock(mutex_t *m)
	__releases(m)
{
#ifdef CONFIG_DEBUG_MUTEX
	if (unlikely(!atomic_load(&m->locked))) {
		fprintf(stderr, "mutex_unlock: mutex is not locked!\n");
		abort();
	}
	atomic_store(&m->locked, false);
#endif

	return pthread_mutex_unlock(&m->mutex);
}

int mutex_trylock(mutex_t *m)
{
	int ret;

	ret = pthread_mutex_trylock(&m->mutex);

#ifdef CONFIG_DEBUG_MUTEX
	if (!ret) {
		if (unlikely(atomic_load(&m->locked))) {
			fprintf(stderr, "mutex_trylock: mutex is already locked!\n");
			abort();
		}
		atomic_store(&m->locked, true);
	}
#endif
	return ret;
}

int cond_init(cond_t *c)
{
	return pthread_cond_init(&c->cond, NULL);
}

int cond_destroy(cond_t *c)
{
	return pthread_cond_destroy(&c->cond);
}

int cond_wait(cond_t *c, mutex_t *m)
	__must_hold(m)
{
#ifdef CONFIG_DEBUG_MUTEX
	if (unlikely(!atomic_load(&m->locked))) {
		fprintf(stderr, "cond_wait: mutex is not locked!\n");
		abort();
	}
#endif

	return pthread_cond_wait(&c->cond, &m->mutex);
}

int cond_signal(cond_t *c)
{
	return pthread_cond_signal(&c->cond);
}

int cond_broadcast(cond_t *c)
{
	return pthread_cond_broadcast(&c->cond);
}
