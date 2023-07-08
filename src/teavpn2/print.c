
#include <time.h>
#include <string.h>
#include <pthread.h>
#include <teavpn2/print.h>

uint8_t __log_level = __LOG_INFO;

static pthread_mutex_t get_time_lock = PTHREAD_MUTEX_INITIALIZER;
static const char __log_level_str[][8] = {
	"emerg",
	"error",
	"warn ",
	"info ",
	"debug",
};

void set_log_level(uint8_t level)
{
	__log_level = level;
}

static __always_inline char *get_time(char *buf)
	__must_hold(&print_lock)
{
	struct tm *timeinfo;
	time_t rawtime;
	char *time_chr;
	size_t len;

	pthread_mutex_lock(&get_time_lock);
	time(&rawtime);
	timeinfo = localtime(&rawtime);
	time_chr = asctime(timeinfo);
	len = strnlen(time_chr, 32) - 1;
	memcpy(buf, time_chr, len);
	buf[len] = '\0';
	pthread_mutex_unlock(&get_time_lock);
	return buf;
}

#ifdef CONFIG_LOG_FILE_AND_LINE
void __pr_log(uint8_t level, const char *file, int lineno, const char *fmt, ...)
{
	char buf[3072], time_buf[32];
	const char *lv;
	va_list arg;

	va_start(arg, fmt);
	vsnprintf(buf, sizeof(buf), fmt, arg);
	va_end(arg);

	get_time(time_buf);

	if (level < ARRAY_SIZE(__log_level_str))
		lv = __log_level_str[level - 1];
	else
		lv = "UNDEF";

	fprintf(stdout, "[%s][%s][%s:%d] %s\n", time_buf, lv, file, lineno, buf);
}
#else
void __pr_log(uint8_t level, const char *fmt, ...)
{
	char buf[3072], time_buf[32];
	const char *lv;
	va_list arg;

	va_start(arg, fmt);
	vsnprintf(buf, sizeof(buf), fmt, arg);
	va_end(arg);

	get_time(time_buf);

	if (level < ARRAY_SIZE(__log_level_str))
		lv = __log_level_str[level - 1];
	else
		lv = "UNDEF";

	fprintf(stdout, "[%s][%s] %s\n", time_buf, lv, buf);
}
#endif
