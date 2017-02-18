#include <config.h>
#include "ucarp.h"
#include "spawn.h"
#ifdef HAVE_SYS_WAIT_H
# include <sys/wait.h>
#endif
#include "log.h"

#ifdef WITH_DMALLOC
# include <dmalloc.h>
#endif

/* grace period between SIGTERM and SIGKILL after a timeout */
#define SCRIPT_KILL_GRACE_MS 500

static long ms_since(const struct timeval * const start)
{
    struct timeval tv, d;

    if (gettimeofday(&tv, NULL) != 0) {
        return 0L;
    }
    timersub(&tv, start, &d);

    return (long) d.tv_sec * 1000L + (long) d.tv_usec / 1000L;
}

/*
 * Wait for <pid> for at most <limit_ms> milliseconds (<= 0: forever).
 * Returns 1 when the child has been reaped, 0 on timeout.
 */
static int wait_child(const pid_t pid, const long limit_ms, int *status)
{
    struct timeval start;
    pid_t r;

    if (limit_ms <= 0L) {
        while ((r = waitpid(pid, status, 0)) == (pid_t) -1 && errno == EINTR);
        return 1;
    }
    (void) gettimeofday(&start, NULL);
    for (;;) {
        r = waitpid(pid, status, WNOHANG);
        if (r == pid || (r == (pid_t) -1 && errno != EINTR)) {
            return 1;
        }
        if (ms_since(&start) >= limit_ms) {
            return 0;
        }
        (void) poll(NULL, (nfds_t) 0, 20);
    }
}

int spawn_handler(const int dev_desc_fd, const char * const script)
{
    pid_t pid;
    int status = 0;
    struct timeval start;

    if (script == NULL || *script == 0) {
        return 0;
    }
    pid = fork();
    if (pid == (pid_t) 0) {
        /*
         * Own process group, so that on timeout the script *and*
         * everything it started (sleep, ping, ...) can be killed at once.
         */
        (void) setpgid(0, 0);
        /*
         * The control port sets SIGPIPE to SIG_IGN, and ignored signals
         * survive exec(). Restore the default so scripts behave exactly
         * as they would when started from a shell.
         */
        (void) signal(SIGPIPE, SIG_DFL);
        (void) close(dev_desc_fd);
        execl(script, script, interface, vaddr_arg, xparam, (char *) NULL);
        logfile(LOG_ERR, _("Unable to exec %s %s %s%s%s: %s"),
                script, interface, vaddr_arg,
                (xparam ? " " : ""), (xparam ? xparam : ""),
                strerror(errno));
        _exit(EXIT_FAILURE);
    } else if (pid == (pid_t) -1) {
        logfile(LOG_ERR, _("Unable to spawn the script: %s"),
                strerror(errno));
        return -1;
    }
    /* also set it from the parent: avoids a race with kill() below */
    (void) setpgid(pid, pid);
    logfile(LOG_WARNING, _("Spawning [%s %s %s%s%s]"),
            script, interface, vaddr_arg,
            (xparam ? " " : ""), (xparam ? xparam : ""));
    (void) gettimeofday(&start, NULL);

    if (wait_child(pid, (long) script_timeout * 1000L, &status) != 0) {
        return 0;
    }

    /* timed out */
    logfile(LOG_ERR, _("Script [%s] did not finish within %u second(s): "
                       "killing it (process group %ld)"),
            script, script_timeout, (long) pid);
    (void) kill(-pid, SIGTERM);
    if (wait_child(pid, (long) SCRIPT_KILL_GRACE_MS, &status) == 0) {
        logfile(LOG_ERR, _("Script [%s] ignored SIGTERM: sending SIGKILL"),
                script);
        (void) kill(-pid, SIGKILL);
        (void) wait_child(pid, 0L, &status);
    } else {
        /* the script is gone; make sure its leftovers are too */
        (void) kill(-pid, SIGKILL);
    }
    logfile(LOG_ERR, _("Script [%s] killed after %ld ms"),
            script, ms_since(&start));

    return -1;
}
