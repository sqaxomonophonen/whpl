/*
This software is in the public domain. Where that dedication is not recognized,
you are granted a perpetual, irrevocable license to copy and modify this file
as you see fit.
*/

#ifndef _LOG_H_
#define _LOG_H_

enum lvl_t {
	DEBUG = 1,
	INFO = 2,
	WARNING = 3,
	ERROR = 4,
	CRITICAL = 5
};

#define PRINTF_LIKE_FMT __attribute__((format(printf, 1, 2)))
#define NO_RETURN __attribute__((noreturn))
void dbgf(const char *fmt, ...) PRINTF_LIKE_FMT;
void infof(const char *fmt, ...) PRINTF_LIKE_FMT;
void warnf(const char *fmt, ...) PRINTF_LIKE_FMT;
void errf(const char *fmt, ...) PRINTF_LIKE_FMT;
void critf(const char *fmt, ...) PRINTF_LIKE_FMT NO_RETURN;

void setloglvl(enum lvl_t lvl);

#endif /* _LOG_H_ */
