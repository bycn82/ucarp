#ifndef __CHECK_H__
#define __CHECK_H__ 1

/*
 * Health check (--check): a script run every --checkinterval seconds,
 * asynchronously. --checkfall consecutive failures put this host in
 * "health down" (stay BACKUP, never take over); --checkrise consecutive
 * successes clear it.
 */

/* result of the last run */
#define CHECK_RES_NONE    0     /* not run yet */
#define CHECK_RES_OK      1     /* exit status 0 */
#define CHECK_RES_FAIL    2     /* non-zero exit status or killed by signal */
#define CHECK_RES_TIMEOUT 3     /* killed after --checktimeout */

struct check_status {
    int down;                   /* 1 = health down: promotion refused */
    time_t down_since;          /* when it went down, 0 = up */
    unsigned int fails;         /* consecutive failures */
    unsigned int oks;           /* consecutive successes */
    int running;                /* 1 = a check is running now */
    int last_result;            /* CHECK_RES_* */
    int last_rc;                /* exit status, or -signal, -1 = none */
    long last_ms;               /* duration of the last run */
    time_t last_time;           /* when the last run finished */
    unsigned long runs;
    unsigned long failures;     /* including timeouts */
    unsigned long timeouts;
};

void check_init(int dev_fd);            /* call once, after pcap is open */
void check_tick(void);                  /* call from every wait loop */
int  check_poll_timeout(int cur_ms);    /* cap a poll() timeout */
void check_shutdown(void);              /* kill a running check */
const struct check_status *check_get_status(void);
const char *check_result_str(int res);

/* provided by carp.c */
void carp_health_set(int down);

#endif
