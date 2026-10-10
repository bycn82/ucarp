/*
 * Health check for UCARP (--check), similar to keepalived's track_script.
 *
 * The script is started every --checkinterval seconds without blocking:
 * the main loop (and ctrl_serve_for()) call check_tick(), which reaps a
 * finished run, kills a run that exceeded --checktimeout, and starts the
 * next one when it is due. Runs never overlap.
 *
 * Script arguments are the same as for the up/down scripts
 * (<interface> <vaddr> [<xparam>]); environment: UCARP_VHID and
 * UCARP_STATE (INIT/BACKUP/MASTER). Exit status 0 means healthy.
 *
 * After --checkfall consecutive failures (non-zero exit, signal or
 * timeout) carp_health_set(1) is called: a MASTER steps down and the host
 * refuses to take over. After --checkrise consecutive successes
 * carp_health_set(0) resumes normal election.
 *
 * The state is "healthy" until the first --checkfall failures, so a host
 * can become MASTER right after startup before the check had a chance to
 * fail.
 */

#include <config.h>
#include "ucarp.h"
#ifdef HAVE_SYS_WAIT_H
# include <sys/wait.h>
#endif
#include "check.h"
#include "ctrl.h"
#include "log.h"

#ifdef WITH_DMALLOC
# include <dmalloc.h>
#endif

/* while a check runs, poll at least this often to reap it promptly */
#define CHECK_REAP_MS 50

static struct check_status cst;
static pid_t check_pid = -1;
static struct timeval check_started;
static struct timeval check_next;       /* when the next run is due */
static int dev_fd = -1;                 /* pcap fd, closed in the child */

static void tv_add_ms(struct timeval * const tv, const long ms)
{
    tv->tv_sec += ms / 1000L;
    tv->tv_usec += (ms % 1000L) * 1000L;
    if (tv->tv_usec >= 1000000) {
        tv->tv_sec++;
        tv->tv_usec -= 1000000;
    }
}

/* milliseconds from <a> to <b>, may be negative */
static long tv_diff_ms(const struct timeval * const a,
                       const struct timeval * const b)
{
    return (long) (b->tv_sec - a->tv_sec) * 1000L +
           (long) (b->tv_usec - a->tv_usec) / 1000L;
}

const char *check_result_str(const int res)
{
    switch (res) {
    case CHECK_RES_OK:
        return "ok";
    case CHECK_RES_FAIL:
        return "fail";
    case CHECK_RES_TIMEOUT:
        return "timeout";
    }
    return "none";
}

const struct check_status *check_get_status(void)
{
    return &cst;
}

void check_init(const int fd)
{
    dev_fd = fd;
    cst.last_rc = -1;
    if (check_script == NULL) {
        return;
    }
    /* first run right away */
    (void) gettimeofday(&check_next, NULL);
    logfile(LOG_INFO, _("Health check [%s] every %us, timeout %us, "
                        "fall %u, rise %u"),
            check_script, check_interval, check_timeout,
            check_fall, check_rise);
}

static void check_finish(int status, int timed_out);

static void check_start(const struct timeval * const tv)
{
    pid_t pid;

    check_next = *tv;
    tv_add_ms(&check_next, (long) check_interval * 1000L);

    pid = fork();
    if (pid == (pid_t) 0) {
        static char vhid_env[sizeof "UCARP_VHID=255"];
        static char state_env[sizeof "UCARP_STATE=UNKNOWN"];

        /* own process group: a timeout kills the script and its children */
        (void) setpgid(0, 0);
        /* the control port ignores SIGPIPE; scripts get the default */
        (void) signal(SIGPIPE, SIG_DFL);
        snprintf(vhid_env, sizeof vhid_env, "UCARP_VHID=%u",
                 (unsigned int) vhid);
        snprintf(state_env, sizeof state_env, "UCARP_STATE=%s",
                 carp_state_name());
        (void) putenv(vhid_env);
        (void) putenv(state_env);
        if (dev_fd != -1) {
            (void) close(dev_fd);
        }
        execl(check_script, check_script, interface, vaddr_arg, xparam,
              (char *) NULL);
        logfile(LOG_ERR, _("Unable to exec health check %s: %s"),
                check_script, strerror(errno));
        _exit(127);
    }
    if (pid == (pid_t) -1) {
        logfile(LOG_ERR, _("Unable to start the health check: %s"),
                strerror(errno));
        /* counts as a failure: a host that can't fork isn't healthy */
        check_started = *tv;
        check_finish(-1, 0);
        return;
    }
    /* parent too: no race with kill(-pid) on a very early timeout */
    (void) setpgid(pid, pid);
    check_pid = pid;
    check_started = *tv;
    cst.running = 1;
}

/* a run finished (or was killed): update counters and the health state */
static void check_finish(const int status, const int timed_out)
{
    struct timeval tv;
    int ok;

    (void) gettimeofday(&tv, NULL);
    check_pid = -1;
    cst.running = 0;
    cst.runs++;
    cst.last_ms = tv_diff_ms(&check_started, &tv);
    cst.last_time = time(NULL);
    if (timed_out) {
        cst.last_result = CHECK_RES_TIMEOUT;
        cst.last_rc = -1;
        cst.timeouts++;
        ok = 0;
    } else if (status != -1 && WIFEXITED(status)) {
        cst.last_rc = WEXITSTATUS(status);
        ok = cst.last_rc == 0;
        cst.last_result = ok ? CHECK_RES_OK : CHECK_RES_FAIL;
    } else {
        cst.last_rc = (status != -1 && WIFSIGNALED(status)) ?
            -WTERMSIG(status) : -1;
        cst.last_result = CHECK_RES_FAIL;
        ok = 0;
    }

    if (ok) {
        cst.fails = 0U;
        if (cst.oks < UINT_MAX) {
            cst.oks++;
        }
        if (cst.down) {
            logfile(LOG_INFO, _("Health check OK (%u/%u)"),
                    cst.oks, check_rise);
            if (cst.oks >= check_rise) {
                cst.down = 0;
                cst.down_since = 0;
                logfile(LOG_WARNING, _("Health check recovered: "
                                       "resuming election"));
                carp_health_set(0);
            }
        }
        return;
    }
    cst.failures++;
    cst.oks = 0U;
    if (cst.fails < UINT_MAX) {
        cst.fails++;
    }
    if (cst.down) {
        return;                 /* already down: don't flood the log */
    }
    if (cst.last_result == CHECK_RES_TIMEOUT) {
        logfile(LOG_WARNING, _("Health check [%s] timed out after %us "
                               "(%u/%u)"),
                check_script, check_timeout, cst.fails, check_fall);
    } else {
        logfile(LOG_WARNING, _("Health check [%s] failed, status %d "
                               "(%u/%u)"),
                check_script, cst.last_rc, cst.fails, check_fall);
    }
    if (cst.fails >= check_fall) {
        cst.down = 1;
        cst.down_since = time(NULL);
        logfile(LOG_WARNING, _("Health check failed %u time(s): "
                               "health down, staying BACKUP"), cst.fails);
        carp_health_set(1);
    }
}

void check_tick(void)
{
    struct timeval tv;
    int status = 0;
    pid_t r;

    if (check_script == NULL) {
        return;
    }
    if (gettimeofday(&tv, NULL) != 0) {
        return;
    }
    if (check_pid != -1) {
        r = waitpid(check_pid, &status, WNOHANG);
        if (r == check_pid) {
            check_finish(status, 0);
        } else if (r == (pid_t) -1 && errno != EINTR) {
            /* child lost (should not happen): count it as a failure */
            check_finish(-1, 0);
        } else if (tv_diff_ms(&check_started, &tv) >=
                   (long) check_timeout * 1000L) {
            /* timeout: kill the whole process group, it's only a check */
            (void) kill(-check_pid, SIGKILL);
            while (waitpid(check_pid, &status, 0) == (pid_t) -1 &&
                   errno == EINTR);
            check_finish(status, 1);
        }
    }
    if (check_pid == -1 && !timercmp(&tv, &check_next, <)) {
        check_start(&tv);
    }
}

/* shorten a poll() timeout so check_tick() runs when needed */
int check_poll_timeout(int cur_ms)
{
    struct timeval tv;
    long ms;

    if (check_script == NULL) {
        return cur_ms;
    }
    if (check_pid != -1) {
        return cur_ms < CHECK_REAP_MS ? cur_ms : CHECK_REAP_MS;
    }
    if (gettimeofday(&tv, NULL) != 0) {
        return cur_ms;
    }
    ms = tv_diff_ms(&tv, &check_next) + 1L;
    if (ms < 0L) {
        ms = 0L;
    }
    return ms < (long) cur_ms ? (int) ms : cur_ms;
}

/* on exit: don't leave a check running */
void check_shutdown(void)
{
    if (check_pid != -1) {
        (void) kill(-check_pid, SIGKILL);
        (void) waitpid(check_pid, NULL, 0);
        check_pid = -1;
    }
}
