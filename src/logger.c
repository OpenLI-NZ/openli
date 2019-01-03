#include "config.h"
#include <stdarg.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <sys/stat.h>
#include <errno.h>

#if HAVE_SYSLOG_H
#include <sys/syslog.h>
#endif

#include "logger.h"

int daemonised = 0;

void remove_pidfile(char *fname) {
    if (unlink(fname) < 0) {
        logger(LOG_INFO, "Error removing pidfile '%s': %s", fname,
                strerror(errno));
    }
}

static int create_pidfile(char *fname) {

    int fd;
    char buf[128];

    if ((fd = open(fname, O_RDWR | O_CREAT | O_CLOEXEC,
            S_IRUSR | S_IWUSR)) < 0) {
        logger(LOG_INFO, "Error opening pidfile '%s': %s",
                fname, strerror(errno));
        return -1;
    }

    if (lockf(fd, F_TLOCK, 0) < 0) {
        if (errno == EACCES || errno == EAGAIN) {
            logger(LOG_DEBUG, "pidfile '%s' is locked, unable to start",
                    fname);
        } else {
            logger(LOG_INFO, "Error while locking pidfile '%s': %s",
                    fname, strerror(errno));
        }
        close(fd);
        return -1;
    }

    if (ftruncate(fd, 0) < 0) {
        logger(LOG_INFO, "Error while truncating pidfile '%s': %s",
                fname, strerror(errno));
        close(fd);
        return -1;
    }

    memset(buf, 0, sizeof(buf));
    snprintf(buf, sizeof(buf) - 1, "%d\n", getpid());
    buf[sizeof(buf) - 1] = '\0';

    if (write(fd, buf, strlen(buf)) < 0) {
        logger(LOG_INFO, "Error while writing to pidfile '%s': %s",
                fname, strerror(errno));
        close(fd);
        return -1;
    }

    close(fd);
    return 0;

}

void open_daemonlog(char *name) {

#if HAVE_SYSLOG_H
    name = strrchr(name,'/') ? strrchr(name,'/') + 1 : name;
    openlog(name, LOG_PID, LOG_DAEMON);
    setlogmask(LOG_UPTO(LOG_INFO));
#else
    (void)(name);
#endif
}


void daemonise(char *name, char *pidfile) {

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

    open_daemonlog(name);
    if (pidfile) {
        if (create_pidfile(pidfile) < 0) {
            exit(0);
        }
    }

    daemonised = 1;
}

void logger(int priority, const char *fmt, ...) {
    va_list ap;
    char buffer[1024];

    va_start(ap, fmt);
    if (daemonised) {
        vsnprintf(buffer, sizeof(buffer), fmt, ap);
#if HAVE_SYSLOG_H
        syslog(priority, "%s", buffer);
#endif
    } else {
        vfprintf(stderr, fmt, ap);
        fprintf(stderr, "\n");
    }
    va_end(ap);

}

// vim: set sw=4 tabstop=4 softtabstop=4 expandtab :

