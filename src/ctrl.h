#ifndef __CTRL_H__
#define __CTRL_H__ 1

/* simultaneous control clients; further connections wait in the backlog */
#define CTRL_MAX_CLIENTS 8
/* pollfd slots the main loop must reserve for the control port */
#define CTRL_MAX_POLLFDS (1 + CTRL_MAX_CLIENTS)

/* return codes of carp_control_master() / carp_control_backup() */
#define CTRL_OK          0     /* success */
#define CTRL_ERR_IFDOWN (-1)   /* interface down: master refused */
#define CTRL_ERR_HOLD   (-2)   /* SIGUSR2 hold: master refused */
#define CTRL_ERR_MAINT  (-3)   /* maintenance mode: master refused */

/* ---- state history and statistics, kept by carp.c ---- */

#define CARP_HIST_MAX 16        /* state transitions remembered */

/* one state transition */
struct carp_transition {
    time_t when;                /* wall clock time of the decision */
    int from;                   /* INIT / BACKUP / MASTER */
    int to;
    const char *reason;         /* see the list at the top of ctrl.c */
    struct in_addr peer;        /* advertiser involved, 0 = none */
};

/* counters and last seen peer */
struct carp_stats {
    time_t started;             /* when docarp() started */
    unsigned long transitions;  /* total, also beyond CARP_HIST_MAX */
    unsigned long adv_sent;     /* advertisements sent */
    unsigned long adv_send_errors;
    unsigned long adv_recv;     /* valid advertisements received */
    unsigned long bad_ttl;
    unsigned long bad_version;
    unsigned long bad_cksum;
    unsigned long bad_auth;     /* HMAC mismatch: password/vhid/VIP differ */
    unsigned long other_vhid;   /* adverts for other vhids on our group */
    struct in_addr last_bad_auth_src;
    time_t last_bad_auth_time;
    int peer_valid;             /* 1 once a valid advert was received */
    struct in_addr peer;        /* source of the last valid advert */
    unsigned int peer_advbase;
    unsigned int peer_advskew;
    struct timeval peer_last;   /* when it was received */
};

/* provided by carp.c */
const char *carp_state_str(int state);
const struct carp_stats *carp_get_stats(void);
int carp_history_count(void);
int carp_control_maint(int on);
int carp_exit_pending(void);            /* 1 = exit signal received */
int carp_maint(void);                   /* 1 = maintenance mode on */
time_t carp_maint_since(void);          /* when it was switched on, 0 = off */
const struct carp_transition *carp_history_get(int i);  /* 0 = newest */
const char *carp_state_name(void);
int  carp_control_master(void);
int  carp_control_backup(void);
int  carp_iface_running(void);

/* provided by ctrl.c */
int  ctrl_init(void);                               /* start listening */
int  ctrl_fill_pollfds(struct pollfd *pfds);        /* add fds, return count */
void ctrl_handle_pollfds(const struct pollfd *pfds); /* handle poll events */
int  ctrl_poll_timeout(int cur_ms);                 /* cap poll timeout */
void ctrl_check_timeout(void);                      /* drop timed-out clients */
void ctrl_serve_for(unsigned int ms);               /* sleep, serving ctrl */

#endif
