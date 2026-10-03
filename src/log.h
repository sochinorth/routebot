#ifndef ROUTEBOT_LOG_H
#define ROUTEBOT_LOG_H

#include <stdio.h>

enum {
	L_ERR,
	L_WARN,
	L_INFO,
	L_DEBUG,
};

extern int log_level;

void log_msg(int level, const char *fmt, ...)
	__attribute__((format(printf, 2, 3)));

#define err(...)	log_msg(L_ERR, __VA_ARGS__)
#define warn(...)	log_msg(L_WARN, __VA_ARGS__)
#define info(...)	log_msg(L_INFO, __VA_ARGS__)
#define debug(...)	do { if (log_level >= L_DEBUG) log_msg(L_DEBUG, __VA_ARGS__); } while (0)

#endif
