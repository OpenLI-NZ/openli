#ifndef LOGGER_H_
#define LOGGER_H_

#if HAVE_SYSLOG_H
#include <sys/syslog.h>
#else
#define LOG_DAEMON (3 << 3)
#endif

extern int daemonised;

void logger(int priority, const char *fmt, ...);
void daemonise(char *name);

#endif

// vim: set sw=4 tabstop=4 softtabstop=4 expandtab :

