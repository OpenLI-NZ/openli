#include "config.h"
#include <stdarg.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <sys/stat.h>

#if HAVE_SYSLOG_H
#include <sys/syslog.h>
#endif

#include "logger.h"

int daemonised = 0;

void daemonise(char *name) {

    int rv;

    switch (fork()) {
        case 0:
            break;
        case -1:
            perror("fork");
            exit(1);
        default:
            _exit(0);
    }
    setsid();
    switch (fork()) {
        case 0:
            break;
        case -1:
            perror("fork2");
            exit(1);
        default:
            _exit(0);
    }
    chdir("/");
    umask(0133);
    close(0);
    close(1);
    close(2);
    rv = open("/dev/null",O_RDONLY);
    assert(rv == 0);
    rv = open("/dev/console",O_WRONLY);
    if (rv == -1) {
        rv=open("/dev/null",O_WRONLY);
    }
    assert(rv == 1);
    rv = dup(rv);
    assert(rv == 2);

    daemonised = 1;
    name = strrchr(name,'/') ? strrchr(name,'/') + 1 : name;

#if HAVE_SYSLOG_H
    openlog(name, LOG_PID, LOG_DAEMON);
#endif

}

void logger(int priority, const char *fmt, ...) {
    va_list ap;
    char buffer[1024];

    va_start(ap, fmt);
    if (daemonised) {
        vsnprintf(buffer, sizeof(buffer), fmt, ap);
#if HAVE_SYSLOG_H
        /* Ensure logs have an appropriate priority */
        priority |= LOG_INFO;
        syslog(priority, "%s", buffer);
#endif
    } else {
        vfprintf(stderr, fmt, ap);
        fprintf(stderr, "\n");
    }
    va_end(ap);

}

// vim: set sw=4 tabstop=4 softtabstop=4 expandtab :

