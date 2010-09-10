/*
 * Local control port for UCARP.
 *
 * -c <port> / --ctrlport=<port> : listen on TCP 127.0.0.1:<port>.
 * A client sends one line. If nothing complete arrives within 1 second
 * the connection is closed. Supported commands:
 *
 *   state   -> one line of JSON with the current state and configuration
 *   master  -> promote, then return state JSON
 *   backup  -> demote, then return state JSON
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

#define CTRL_LINE_MAX   256
#define CTRL_TIMEOUT_MS 1000
#define CTRL_OUT_MAX    4096

static int listen_fd = -1;
static int client_fd = -1;
static struct timeval client_deadline;
static char line[CTRL_LINE_MAX];
static size_t line_len;

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

int ctrl_init(void)
{
    struct sockaddr_in sin;
    int on = 1;

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
        listen(listen_fd, 5) != 0 || set_fd_flags(listen_fd) != 0) {
        logfile(LOG_ERR, _("ctrl: unable to listen on 127.0.0.1:%u: %s"),
                ctrl_port, strerror(errno));
        (void) close(listen_fd);
        listen_fd = -1;
        return -1;
    }
    /* a client closing early must not kill us on write() */
    (void) signal(SIGPIPE, SIG_IGN);
    logfile(LOG_INFO, _("ctrl: listening on 127.0.0.1:%u"), ctrl_port);

    return 0;
}

int ctrl_listen_fd(void)
{
    return listen_fd;
}

int ctrl_client_fd(void)
{
    return client_fd;
}

static void client_close(void)
{
    if (client_fd != -1) {
        (void) close(client_fd);
        client_fd = -1;
    }
    line_len = 0U;
}

/* shrink the main loop's poll timeout so the 1s client timeout is honoured */
int ctrl_poll_timeout(int cur_ms)
{
    struct timeval tv, left;
    int ms;

    if (client_fd == -1) {
        return cur_ms;
    }
    if (gettimeofday(&tv, NULL) != 0) {
        return cur_ms;
    }
    if (timercmp(&tv, &client_deadline, >)) {
        return 0;
    }
    timersub(&client_deadline, &tv, &left);
    ms = (int) (left.tv_sec * 1000 + left.tv_usec / 1000) + 1;

    return ms < cur_ms ? ms : cur_ms;
}

void ctrl_on_accept(void)
{
    struct timeval tv;
    int fd;

    if (listen_fd == -1) {
        return;
    }
    if ((fd = accept(listen_fd, NULL, NULL)) == -1) {
        return;
    }
    if (client_fd != -1) {
        /* one client at a time; the current one expires within 1s */
        (void) close(fd);
        return;
    }
    if (set_fd_flags(fd) != 0) {
        (void) close(fd);
        return;
    }
    client_fd = fd;
    line_len = 0U;
    (void) gettimeofday(&tv, NULL);
    client_deadline.tv_sec = tv.tv_sec + CTRL_TIMEOUT_MS / 1000;
    client_deadline.tv_usec = tv.tv_usec + (CTRL_TIMEOUT_MS % 1000) * 1000;
    if (client_deadline.tv_usec >= 1000000) {
        client_deadline.tv_sec++;
        client_deadline.tv_usec -= 1000000;
    }
}

void ctrl_check_timeout(void)
{
    struct timeval tv;

    if (client_fd == -1) {
        return;
    }
    if (gettimeofday(&tv, NULL) == 0 && timercmp(&tv, &client_deadline, >)) {
        client_close();
    }
}

/* ---- tiny JSON writer ---- */

struct out {
    char buf[CTRL_OUT_MAX];
    size_t len;
};

static void out_raw(struct out *o, const char *s)
{
    size_t l = strlen(s);

    if (o->len + l >= sizeof o->buf) {
        l = sizeof o->buf - 1U - o->len;
    }
    memcpy(o->buf + o->len, s, l);
    o->len += l;
    o->buf[o->len] = 0;
}

static void out_str(struct out *o, const char *s)
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
        } else if (c < 0x20U) {
            snprintf(esc, sizeof esc, "\\u%04x", (unsigned int) c);
        } else {
            esc[0] = (char) c;
            esc[1] = 0;
        }
        out_raw(o, esc);
    }
    out_raw(o, "\"");
}

static void out_key(struct out *o, const char *k, const int first)
{
    if (!first) {
        out_raw(o, ",");
    }
    out_str(o, k);
    out_raw(o, ":");
}

static void out_kstr(struct out *o, const char *k, const char *v)
{
    out_key(o, k, 0);
    out_str(o, v);
}

static void out_kuint(struct out *o, const char *k, const unsigned long v)
{
    char tmp[32];

    snprintf(tmp, sizeof tmp, "%lu", v);
    out_key(o, k, 0);
    out_raw(o, tmp);
}

static void out_kbool(struct out *o, const char *k, const int v)
{
    out_key(o, k, 0);
    out_raw(o, v ? "true" : "false");
}

static void build_state(struct out *o)
{
    char ip[INET_ADDRSTRLEN];
    char mac[18];

    o->len = 0U;
    o->buf[0] = 0;
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
    out_kbool(o, "nomcast", no_mcast != 0);
    out_kbool(o, "daemonize", daemonize != 0);
    out_kstr(o, "upscript", upscript);
    out_kstr(o, "downscript", downscript);
    out_kstr(o, "xparam", xparam);
    snprintf(mac, sizeof mac, "%02x:%02x:%02x:%02x:%02x:%02x",
             (unsigned int) hwaddr[0], (unsigned int) hwaddr[1],
             (unsigned int) hwaddr[2], (unsigned int) hwaddr[3],
             (unsigned int) hwaddr[4], (unsigned int) hwaddr[5]);
    out_kstr(o, "hwaddr", mac);
    out_kuint(o, "ctrlport", (unsigned long) ctrl_port);
    out_kuint(o, "pid", (unsigned long) getpid());
    out_raw(o, "}\n");
}

static void reply(const char *buf, size_t len)
{
    ssize_t w;

    /* response is small; a fresh socket buffer always takes it at once */
    while (len > 0U) {
        w = write(client_fd, buf, len);
        if (w < 0) {
            if (errno == EINTR) {
                continue;
            }
            return;
        }
        buf += w;
        len -= (size_t) w;
    }
}

static void process_line(void)
{
    static struct out o;
    char *s = line;
    char *e;

    line[line_len] = 0;
    while (*s == ' ' || *s == '\t') {
        s++;
    }
    e = s + strlen(s);
    while (e > s && (e[-1] == '\n' || e[-1] == '\r' ||
                     e[-1] == ' ' || e[-1] == '\t')) {
        *--e = 0;
    }
    if (strcmp(s, "state") == 0 || strcmp(s, "master") == 0 ||
        strcmp(s, "backup") == 0) {
        if (strcmp(s, "master") == 0) {
            carp_control_master();
        } else if (strcmp(s, "backup") == 0) {
            carp_control_backup();
        }
        build_state(&o);
        reply(o.buf, o.len);
    } else {
        static const char err[] = "{\"error\":\"unknown command\"}\n";
        reply(err, sizeof err - 1U);
    }
    client_close();
}

void ctrl_on_readable(void)
{
    ssize_t r;
    char *nl;

    if (client_fd == -1) {
        return;
    }
    for (;;) {
        r = read(client_fd, line + line_len, sizeof line - 1U - line_len);
        if (r < 0) {
            if (errno == EINTR) {
                continue;
            }
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                return;
            }
            client_close();
            return;
        }
        if (r == 0) {
            /* EOF: accept "state" without trailing newline */
            if (line_len > 0U) {
                process_line();
            } else {
                client_close();
            }
            return;
        }
        line_len += (size_t) r;
        line[line_len] = 0;
        if ((nl = strchr(line, '\n')) != NULL) {
            *nl = 0;
            line_len = (size_t) (nl - line);
            process_line();
            return;
        }
        if (line_len >= sizeof line - 1U) {
            process_line();   /* overlong line -> unknown command */
            return;
        }
    }
}
