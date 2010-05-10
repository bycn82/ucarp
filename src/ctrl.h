#ifndef __CTRL_H__
#define __CTRL_H__ 1

/* provided by carp.c */
const char *carp_state_name(void);

int  ctrl_init(void);
int  ctrl_listen_fd(void);
int  ctrl_client_fd(void);
int  ctrl_poll_timeout(int cur_ms);
void ctrl_on_accept(void);
void ctrl_on_readable(void);
void ctrl_check_timeout(void);

#endif
