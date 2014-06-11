/*
This software is in the public domain. Where that dedication is not recognized,
you are granted a perpetual, irrevocable license to copy and modify this file
as you see fit.
*/

#include "log.h"

#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>

enum lvl_t loglvl;

void log_va(enum lvl_t lvl, const char* fmt, va_list args)
{
	if (lvl < loglvl) return;
	FILE* out = stderr;
	switch (lvl) {
		case DEBUG:
			fprintf(out, "[DEBUG] ");
			break;
		case INFO:
			fprintf(out, "[INFO] ");
			break;
		case WARNING:
			fprintf(out, "[WARNING] ");
			break;
		case ERROR:
			fprintf(out, "[ERROR] ");
			break;
		case CRITICAL:
			fprintf(out, "[CRITICAL] ");
			break;
		default:
			fprintf(out, "[?!] ");
			break;
	}
	vfprintf(out, fmt, args);
	fprintf(out, "\n");
	fflush(out);
}

void dbgf(const char *fmt, ...)
{
	va_list args;
	va_start(args, fmt);
	log_va(DEBUG, fmt, args);
	va_end(args);
}

void infof(const char *fmt, ...)
{
	va_list args;
	va_start(args, fmt);
	log_va(INFO, fmt, args);
	va_end(args);
}

void warnf(const char *fmt, ...)
{
	va_list args;
	va_start(args, fmt);
	log_va(WARNING, fmt, args);
	va_end(args);
}

void errf(const char *fmt, ...)
{
	va_list args;
	va_start(args, fmt);
	log_va(ERROR, fmt, args);
	va_end(args);
}

void critf(const char *fmt, ...)
{
	va_list args;
	va_start(args, fmt);
	log_va(CRITICAL, fmt, args);
	va_end(args);
	exit(255);
}

void setloglvl(enum lvl_t lvl)
{
	loglvl = lvl;
}


