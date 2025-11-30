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

/* provided by carp.c */
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
