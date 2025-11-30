/*
 * Copyright (c) 2010-2015 Bill Yuan. All rights reserved.
 *
 * Local control port for UCARP.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR OR HIS RELATIVES BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF MIND, USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
 * IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF
 * THE POSSIBILITY OF SUCH DAMAGE.
 *
 * Local control port for UCARP.
 *
 * -c <port> / --ctrlport=<port> : listen on TCP 127.0.0.1:<port>.
 * A client sends one line and gets one line of JSON back, then the
 * connection is closed. Commands:
 *
 *   state          -> current state and configuration
 *   master <key>   -> promote, then return state
 *   backup <key>   -> demote, then return state
 *
 * master/backup need the key read from -K/--ctrlkeyfile; without a key
 * file they are disabled. "state" needs no key.
 *
 * Up to CTRL_MAX_CLIENTS clients are served at once; further connections
 * wait in the listen backlog. A client has 1 second to send its line and
 * 1 second to read the reply.
 *
 * Everything is non-blocking and driven by the main poll() loop in carp.c,
 * so a slow client never delays CARP advertisements.
 */

#include <config.h>
#include "ucarp.h"
#include "ctrl.h"
#include "log.h"

#ifdef WITH_DMALLOC
# include <dmalloc.h>
#endif

#define CTRL_LINE_MAX   256     /* max command line length, incl. NUL */
#define CTRL_TIMEOUT_MS 1000    /* time to send a command / read a reply */
#define CTRL_BACKLOG    16      /* listen() backlog */

/* client slot state: free / reading the command / writing the reply */
enum { CL_FREE = 0, CL_READING, CL_WRITING };

/* one control port connection */
struct client {
    int fd;                     /* connected socket */
    int st;                     /* CL_FREE / CL_READING / CL_WRITING */
    struct timeval deadline;    /* deadline of the current phase */
    char in[CTRL_LINE_MAX];     /* command line received so far */
    size_t in_len;
    char *out;                  /* reply to send (malloc'ed) */
    size_t out_len;
    size_t out_off;             /* bytes already sent */
    int pfd;                    /* index in the pollfd array, -1 = not polled */
};

static int listen_fd = -1;      /* listening socket, -1 = control port off */
static int listen_pfd = -1;     /* its index in the pollfd array */
static struct client clients[CTRL_MAX_CLIENTS];
static int nclients;            /* slots in use */

/* non-blocking + close-on-exec */
static int set_fd_flags(const int fd)
{
    int fl;

    if ((fl = fcntl(fd, F_GETFL, 0)) == -1 ||
        fcntl(fd, F_SETFL, fl | O_NONBLOCK) == -1) {
        return -1;
    }
    /* don't leak control sockets into up/down scripts */
    if (fcntl(fd, F_SETFD, FD_CLOEXEC) == -1) {
        return -1;
    }
    return 0;
}

/* deadline = now + CTRL_TIMEOUT_MS */
static void set_deadline(struct timeval * const d)
{
    (void) gettimeofday(d, NULL);
    d->tv_sec += CTRL_TIMEOUT_MS / 1000;
    d->tv_usec += (CTRL_TIMEOUT_MS % 1000) * 1000;
    if (d->tv_usec >= 1000000) {
        d->tv_sec++;
        d->tv_usec -= 1000000;
    }
}

/* reset the client table; with -c, listen on 127.0.0.1 */
int ctrl_init(void)
{
    struct sockaddr_in sin;
    int on = 1;
    int i;

    for (i = 0; i < CTRL_MAX_CLIENTS; i++) {
        clients[i].fd = -1;
        clients[i].st = CL_FREE;
        clients[i].out = NULL;
        clients[i].pfd = -1;
    }
    if (ctrl_port == 0U) {
        return 0;
    }
    if ((listen_fd = socket(PF_INET, SOCK_STREAM, 0)) == -1) {
        logfile(LOG_ERR, _("ctrl: socket(): %s"), strerror(errno));
        return -1;
    }
    (void) setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof on);
    memset(&sin, 0, sizeof sin);
    sin.sin_family = AF_INET;
    sin.sin_port = htons((unsigned short) ctrl_port);
    sin.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (bind(listen_fd, (struct sockaddr *) &sin, sizeof sin) != 0 ||
        listen(listen_fd, CTRL_BACKLOG) != 0 ||
        set_fd_flags(listen_fd) != 0) {
        logfile(LOG_ERR, _("ctrl: unable to listen on 127.0.0.1:%u: %s"),
                ctrl_port, strerror(errno));
        (void) close(listen_fd);
        listen_fd = -1;
        return -1;
    }
    /* a client closing early must not kill us on write();
     * spawn.c restores the default for the scripts */
    (void) signal(SIGPIPE, SIG_IGN);
    logfile(LOG_INFO, _("ctrl: listening on 127.0.0.1:%u%s"), ctrl_port,
            ctrl_key == NULL ? _(" (master/backup disabled: no key file)")
                             : "");

    return 0;
}

/* close the connection, free the reply, release the slot */
static void client_close(struct client * const c)
{
    if (c->fd != -1) {
        (void) close(c->fd);
    }
    free(c->out);
    c->out = NULL;
    c->fd = -1;
    c->st = CL_FREE;
    c->pfd = -1;
    nclients--;
}

/* ---- growing output buffer: never truncates ---- */

struct out {
    char *buf;      /* malloc'ed, always NUL-terminated */
    size_t len;     /* bytes written */
    size_t cap;     /* bytes allocated */
    int oom;        /* out of memory: further writes are ignored */
};

/* append <l> bytes, doubling the buffer when needed */
static void out_raw_n(struct out * const o, const char *s, size_t l)
{
    if (o->oom) {
        return;
    }
    if (o->len + l + 1U > o->cap) {
        size_t ncap = o->cap ? o->cap : 1024U;
        char *nb;

        while (o->len + l + 1U > ncap) {
            ncap *= 2U;
        }
        if ((nb = realloc(o->buf, ncap)) == NULL) {
            o->oom = 1;
            return;
        }
        o->buf = nb;
        o->cap = ncap;
    }
    memcpy(o->buf + o->len, s, l);
    o->len += l;
    o->buf[o->len] = 0;
}

static void out_raw(struct out * const o, const char *s)
{
    out_raw_n(o, s, strlen(s));
}

/* JSON string: escape quote, backslash and control chars; NULL -> null */
static void out_str(struct out * const o, const char *s)
{
    char esc[8];

    if (s == NULL) {
        out_raw(o, "null");
        return;
    }
    out_raw(o, "\"");
    for (; *s != 0; s++) {
        const unsigned char c = (unsigned char) *s;

        if (c == '"' || c == '\\') {
            esc[0] = '\\';
            esc[1] = (char) c;
            esc[2] = 0;
        } else if (c < 0x20U || c == 0x7fU) {
            snprintf(esc, sizeof esc, "\\u%04x", (unsigned int) c);
        } else {
            esc[0] = (char) c;
            esc[1] = 0;
        }
        out_raw(o, esc);
    }
    out_raw(o, "\"");
}

/* "key": , preceded by a comma unless it is the first key */
static void out_key(struct out * const o, const char *k, const int first)
{
    if (!first) {
        out_raw(o, ",");
    }
    out_str(o, k);
    out_raw(o, ":");
}

static void out_kstr(struct out * const o, const char *k, const char *v)
{
    out_key(o, k, 0);
    out_str(o, v);
}

static void out_kuint(struct out * const o, const char *k,
                      const unsigned long v)
{
    char tmp[32];

    snprintf(tmp, sizeof tmp, "%lu", v);
    out_key(o, k, 0);
    out_raw(o, tmp);
}

static void out_kbool(struct out * const o, const char *k, const int v)
{
    out_key(o, k, 0);
    out_raw(o, v ? "true" : "false");
}

/* JSON reply of "state": a single line ending with a newline */
static void build_state(struct out * const o)
{
    char ip[INET_ADDRSTRLEN];
    char mac[18];

    out_raw(o, "{");
    out_key(o, "state", 1);
    out_str(o, carp_state_name());
    out_kstr(o, "interface", interface);
    if (inet_ntop(AF_INET, &srcip, ip, sizeof ip) == NULL) {
        ip[0] = 0;
    }
    out_kstr(o, "srcip", ip);
    out_kstr(o, "vaddr", vaddr_arg);
    out_kuint(o, "vhid", (unsigned long) vhid);
    out_kuint(o, "advbase", (unsigned long) advbase);
    out_kuint(o, "advskew", (unsigned long) advskew);
    out_kuint(o, "deadratio", (unsigned long) dead_ratio);
    out_kbool(o, "preempt", preempt != 0);
    out_kbool(o, "neutral", neutral != 0);
    out_kbool(o, "shutdown", shutdown_at_exit != 0);
    out_kbool(o, "ignoreifstate", ignoreifstate != 0);
    out_kbool(o, "ifrunning", carp_iface_running() != 0);
    if (inet_ntop(AF_INET, inaddr_carp_group, ip, sizeof ip) == NULL) {
        ip[0] = 0;
    }
    out_kstr(o, "mcast", ip);
    out_kbool(o, "nomcast", no_mcast != 0);
    out_kbool(o, "nospoof", no_spoof != 0);
    out_kbool(o, "daemonize", daemonize != 0);
    out_kstr(o, "upscript", upscript);
    out_kstr(o, "downscript", downscript);
    out_kstr(o, "xparam", xparam);
    snprintf(mac, sizeof mac, "%02x:%02x:%02x:%02x:%02x:%02x",
             (unsigned int) hwaddr[0], (unsigned int) hwaddr[1],
             (unsigned int) hwaddr[2], (unsigned int) hwaddr[3],
             (unsigned int) hwaddr[4], (unsigned int) hwaddr[5]);
    out_kstr(o, "hwaddr", mac);
    out_kuint(o, "scripttimeout", (unsigned long) script_timeout);
    out_kuint(o, "ctrlport", (unsigned long) ctrl_port);
    out_kbool(o, "ctrlauth", ctrl_key != NULL);
    out_kuint(o, "pid", (unsigned long) getpid());
    out_raw(o, "}\n");
}

/* ---- writing ---- */

/*
 * Write as much of the reply as possible. On EAGAIN return 0 and wait for
 * the next POLLOUT; when done or on error, close and return 1.
 */
static int client_flush(struct client * const c)
{
    ssize_t w;

    while (c->out_off < c->out_len) {
        w = write(c->fd, c->out + c->out_off, c->out_len - c->out_off);
        if (w < 0) {
            if (errno == EINTR) {
                continue;
            }
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                return 0;
            }
            client_close(c);
            return 1;
        }
        c->out_off += (size_t) w;
    }
    client_close(c);

    return 1;
}

/* send <o> as the reply (takes ownership of o->buf), switch to writing */
static void client_reply(struct client * const c, struct out * const o)
{
    static const char oom[] = "{\"error\":\"out of memory\"}\n";

    /* out of memory while building: send an error, never half a JSON */
    if (o->oom || o->buf == NULL) {
        free(o->buf);
        o->buf = NULL;
        o->len = 0U;
        if ((o->buf = malloc(sizeof oom)) == NULL) {
            client_close(c);
            return;
        }
        memcpy(o->buf, oom, sizeof oom);
        o->len = sizeof oom - 1U;
    }
    c->out = o->buf;
    c->out_len = o->len;
    c->out_off = 0U;
    c->st = CL_WRITING;
    set_deadline(&c->deadline);   /* 1s for the client to read the reply */
    (void) client_flush(c);
}

/* reply with a fixed string (error messages) */
static void client_reply_str(struct client * const c, const char *s)
{
    struct out o;

    memset(&o, 0, sizeof o);
    out_raw(&o, s);
    client_reply(c, &o);
}

/* ---- authentication ---- */

/* constant-time comparison, so the key can't be guessed byte by byte */
static int key_ok(const char *given)
{
    const unsigned char *a = (const unsigned char *) given;
    const unsigned char *b = (const unsigned char *) ctrl_key;
    size_t la = strlen(given), lb = strlen(ctrl_key), i, n;
    unsigned int diff;

    diff = (unsigned int) (la ^ lb);
    n = la > lb ? la : lb;
    for (i = 0; i < n; i++) {
        diff |= (unsigned int) ((i < la ? a[i] : 0U) ^ (i < lb ? b[i] : 0U));
    }
    return diff == 0U;
}

/* parse and run one command line: "<command> [<key>]" */
static void process_line(struct client * const c)
{
    struct out o;
    char *cmd = c->in;
    char *arg;
    char *e;
    int rc;

    c->in[c->in_len] = 0;
    while (*cmd == ' ' || *cmd == '\t') {
        cmd++;
    }
    e = cmd + strlen(cmd);
    while (e > cmd && (e[-1] == '\n' || e[-1] == '\r' ||
                       e[-1] == ' ' || e[-1] == '\t')) {
        *--e = 0;
    }
    arg = cmd;
    while (*arg != 0 && *arg != ' ' && *arg != '\t') {
        arg++;
    }
    if (*arg != 0) {
        *arg++ = 0;
        while (*arg == ' ' || *arg == '\t') {
            arg++;
        }
    }

    if (strcmp(cmd, "master") == 0 || strcmp(cmd, "backup") == 0) {
        /* no key file: master/backup are disabled */
        if (ctrl_key == NULL) {
            client_reply_str(c, "{\"error\":\"master/backup disabled: "
                             "start ucarp with --ctrlkeyfile\"}\n");
            return;
        }
        /* missing or wrong key: refuse and log */
        if (*arg == 0 || !key_ok(arg)) {
            logfile(LOG_WARNING, _("ctrl: '%s' refused: bad or missing key"),
                    cmd);
            client_reply_str(c, "{\"error\":\"authentication failed\"}\n");
            return;
        }
        logfile(LOG_WARNING, _("ctrl: '%s' requested"), cmd);
        rc = (cmd[0] == 'm') ? carp_control_master() : carp_control_backup();
        if (rc == CTRL_ERR_IFDOWN) {
            client_reply_str(c, "{\"error\":\"interface down\"}\n");
            return;
        }
        if (rc == CTRL_ERR_HOLD) {
            client_reply_str(c, "{\"error\":\"busy: SIGUSR2 hold in "
                             "progress, retry in a few seconds\"}\n");
            return;
        }
    } else if (strcmp(cmd, "state") != 0) {     /* state needs no key */
        client_reply_str(c, "{\"error\":\"unknown command\"}\n");
        return;
    }
    memset(&o, 0, sizeof o);
    build_state(&o);
    client_reply(c, &o);
}

/* read the command; act on newline, EOF or a full buffer */
static void client_read(struct client * const c)
{
    ssize_t r;
    char *nl;

    for (;;) {
        r = read(c->fd, c->in + c->in_len, sizeof c->in - 1U - c->in_len);
        if (r < 0) {
            if (errno == EINTR) {
                continue;
            }
            if (errno != EAGAIN && errno != EWOULDBLOCK) {
                client_close(c);
            }
            return;
        }
        if (r == 0) {
            /* EOF: accept a command without trailing newline */
            if (c->in_len > 0U) {
                process_line(c);
            } else {
                client_close(c);
            }
            return;
        }
        c->in_len += (size_t) r;
        c->in[c->in_len] = 0;
        if ((nl = strchr(c->in, '\n')) != NULL) {
            *nl = 0;
            c->in_len = (size_t) (nl - c->in);
            process_line(c);
            return;
        }
        /* line too long: error, never executed as a command */
        if (c->in_len >= sizeof c->in - 1U) {
            client_reply_str(c, "{\"error\":\"line too long\"}\n");
            return;
        }
    }
}

/* accept connections until no slot is free or none are pending */
static void accept_clients(void)
{
    int fd, i;

    while (nclients < CTRL_MAX_CLIENTS) {
        if ((fd = accept(listen_fd, NULL, NULL)) == -1) {
            return;
        }
        if (set_fd_flags(fd) != 0) {
            (void) close(fd);
            continue;
        }
        for (i = 0; i < CTRL_MAX_CLIENTS; i++) {
            if (clients[i].st == CL_FREE) {
                break;
            }
        }
        clients[i].fd = fd;
        clients[i].st = CL_READING;
        clients[i].in_len = 0U;
        clients[i].out = NULL;
        clients[i].pfd = -1;
        set_deadline(&clients[i].deadline);
        nclients++;
    }
}

/* ---- poll integration ---- */

/*
 * Fill pfds (room for CTRL_MAX_POLLFDS entries) and return how many were
 * used. The listening socket is only polled when a slot is free, so
 * surplus connections simply wait in the backlog instead of being closed.
 * Reading clients wait for POLLIN, writing clients for POLLOUT.
 */
int ctrl_fill_pollfds(struct pollfd *pfds)
{
    int n = 0, i;

    listen_pfd = -1;
    if (listen_fd == -1) {
        return 0;
    }
    if (nclients < CTRL_MAX_CLIENTS) {
        listen_pfd = n;
        pfds[n].fd = listen_fd;
        pfds[n].events = POLLIN;
        pfds[n].revents = 0;
        n++;
    }
    for (i = 0; i < CTRL_MAX_CLIENTS; i++) {
        clients[i].pfd = -1;
        if (clients[i].st == CL_FREE) {
            continue;
        }
        clients[i].pfd = n;
        pfds[n].fd = clients[i].fd;
        pfds[n].events = clients[i].st == CL_READING ? POLLIN : POLLOUT;
        pfds[n].revents = 0;
        n++;
    }
    return n;
}

/* handle poll() results: clients first, then new connections, then
 * timeouts */
void ctrl_handle_pollfds(const struct pollfd *pfds)
{
    int i;
    short ev;

    for (i = 0; i < CTRL_MAX_CLIENTS; i++) {
        struct client * const c = &clients[i];

        if (c->st == CL_FREE || c->pfd < 0) {
            continue;
        }
        ev = pfds[c->pfd].revents;
        c->pfd = -1;
        if (ev == 0) {
            continue;
        }
        if (c->st == CL_READING) {
            client_read(c);
        } else if ((ev & (POLLERR | POLLHUP)) != 0 && (ev & POLLOUT) == 0) {
            client_close(c);
        } else {
            (void) client_flush(c);
        }
    }
    if (listen_pfd >= 0 && (pfds[listen_pfd].revents & POLLIN) != 0) {
        accept_clients();
    }
    listen_pfd = -1;
    ctrl_check_timeout();
}

/* shrink the caller's poll timeout so client deadlines are honoured */
int ctrl_poll_timeout(int cur_ms)
{
    struct timeval tv, left;
    int i, ms;

    if (nclients == 0 || gettimeofday(&tv, NULL) != 0) {
        return cur_ms;
    }
    for (i = 0; i < CTRL_MAX_CLIENTS; i++) {
        if (clients[i].st == CL_FREE) {
            continue;
        }
        if (!timercmp(&tv, &clients[i].deadline, <)) {
            return 0;
        }
        timersub(&clients[i].deadline, &tv, &left);
        ms = (int) (left.tv_sec * 1000 + left.tv_usec / 1000) + 1;
        if (ms < cur_ms) {
            cur_ms = ms;
        }
    }
    return cur_ms;
}

/* close every client past its deadline */
void ctrl_check_timeout(void)
{
    struct timeval tv;
    int i;

    if (nclients == 0 || gettimeofday(&tv, NULL) != 0) {
        return;
    }
    for (i = 0; i < CTRL_MAX_CLIENTS; i++) {
        if (clients[i].st != CL_FREE &&
            timercmp(&tv, &clients[i].deadline, >)) {
            client_close(&clients[i]);
        }
    }
}

/*
 * Replacement for sleep() in carp.c (interface down, SIGUSR2 hold):
 * wait <ms> milliseconds while still serving the control port.
 * Without a control port this is just a sleep.
 */
void ctrl_serve_for(unsigned int ms)
{
    struct timeval end, tv, left;
    struct pollfd pfds[CTRL_MAX_POLLFDS];
    int n, to, r;

    (void) gettimeofday(&end, NULL);
    end.tv_sec += ms / 1000U;
    end.tv_usec += (ms % 1000U) * 1000U;
    if (end.tv_usec >= 1000000) {
        end.tv_sec++;
        end.tv_usec -= 1000000;
    }
    for (;;) {
        if (gettimeofday(&tv, NULL) != 0 || !timercmp(&tv, &end, <)) {
            return;
        }
        timersub(&end, &tv, &left);
        to = (int) (left.tv_sec * 1000 + left.tv_usec / 1000) + 1;
        n = ctrl_fill_pollfds(pfds);
        to = ctrl_poll_timeout(to);
        r = poll(n > 0 ? pfds : NULL, (nfds_t) n, to < 1 ? 1 : to);
        if (r > 0) {
            ctrl_handle_pollfds(pfds);
        } else {
            ctrl_check_timeout();
        }
    }
}
