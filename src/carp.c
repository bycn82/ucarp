/*
 * Copyright (c) 2010-2024 Bill Yuan. All rights reserved.
 * Copyright (c) 2004-2010 Frank Denis. All rights reserved.
 * 
 * This crucial part of UCARP is derived from the OpenBSD project.
 * Original copyright follows. 
 * 
 * Copyright (c) 2002 Michael Shalayeff. All rights reserved.
 * Copyright (c) 2003 Ryan McBride. All rights reserved.
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
 */

#include <config.h>
#include "ucarp.h"
#include "crypto.h"
#ifndef USE_SYSTEM_CRYPT_SHA1
# include "crypto-sha1.h"
#else
# include <sha1.h>
#endif
#include "ip_carp.h"
#include "fillmac.h"
#include "garp.h"
#include "spawn.h"
#include "log.h"
#include "carp_p.h"
#include "ctrl.h"

#ifdef WITH_DMALLOC
# include <dmalloc.h>
#endif

/* Interface state: 1 = up (RUNNING); 0 = down, waiting for it to return */
static int iface_running = 1;
/* Set during the SIGUSR2 hold; "master" is refused (it would be undone) */
static int ctrl_holding;
/*
 * Maintenance mode ("maint on"): stay BACKUP and never take over, until
 * "maint off". Not persistent: a restarted ucarp starts with it off.
 */
static int maint_mode;
static time_t maint_since;
/*
 * Set by the SIGINT/SIGQUIT/SIGTERM handler (-z only). The exit itself is
 * done by carp_shutdown() from the main loop, not in the signal handler:
 * running scripts, logging or sending packets there is not async-signal
 * safe.
 */
static volatile sig_atomic_t exit_signal;
/* Set while sending the final "going away" advertisement */
static int yielding;

/* For ctrl_serve_for(): stop waiting, an exit is pending */
int carp_exit_pending(void)
{
    return exit_signal != 0;
}

/* Interface state for the control port ("ifrunning" in the state reply) */
int carp_iface_running(void)
{
    return iface_running;
}

/* ---- state history and statistics (reported by the control port) ---- */

static struct carp_stats cstats;
static struct carp_transition hist[CARP_HIST_MAX];
static int hist_head;           /* next slot to write */
static int hist_n;              /* valid entries */

/*
 * Why the next carp_set_state() happens, and which advertiser caused it.
 * Every caller of carp_set_state() / carp_master_down() sets this first.
 */
static const char *transition_reason = "startup";
static struct in_addr transition_peer;

#define CARP_REASON(R, PEER) do {                \
        transition_reason = (R);                 \
        transition_peer.s_addr = (PEER);         \
    } while (0)

const char *carp_state_str(const int state)
{
    switch (state) {
    case INIT:
        return "INIT";
    case BACKUP:
        return "BACKUP";
    case MASTER:
        return "MASTER";
    }
    return "UNKNOWN";
}

/* Name of the current CARP state, for the control port "state" command */
const char *carp_state_name(void)
{
    return carp_state_str((int) sc.sc_state);
}

const struct carp_stats *carp_get_stats(void)
{
    return &cstats;
}

int carp_history_count(void)
{
    return hist_n;
}

/* i = 0 is the newest transition */
const struct carp_transition *carp_history_get(const int i)
{
    if (i < 0 || i >= hist_n) {
        return NULL;
    }
    return &hist[(hist_head - 1 - i + 2 * CARP_HIST_MAX) % CARP_HIST_MAX];
}

static void record_transition(const int from, const int to)
{
    struct carp_transition * const t = &hist[hist_head];

    t->when = time(NULL);
    t->from = from;
    t->to = to;
    t->reason = transition_reason != NULL ? transition_reason : "unknown";
    t->peer = transition_peer;
    hist_head = (hist_head + 1) % CARP_HIST_MAX;
    if (hist_n < CARP_HIST_MAX) {
        hist_n++;
    }
    cstats.transitions++;
}

static void carp_set_state(struct carp_softc *sc, int state)
{
    if ((int) sc->sc_state == state) {
        return;
    }
    /* recorded before the scripts run: the time is when we decided */
    record_transition((int) sc->sc_state, state);
    switch (state) {
    case INIT:
        logfile(LOG_INFO, _("Switching to state: INIT"));
        break;
    case BACKUP:
        logfile(LOG_WARNING, _("Switching to state: BACKUP"));
        if ((sc->sc_state != INIT) || (neutral != 1)) {
            (void) spawn_handler(dev_desc_fd, downscript);
        }
        break;
    case MASTER:
        logfile(LOG_WARNING, _("Switching to state: MASTER"));
        (void) spawn_handler(dev_desc_fd, upscript);
        gratuitous_arp(dev_desc_fd);        
        break;
    default:
        logfile(LOG_ERR, _("Unknown state: [%d]"), (int) state);
        abort();
    }
    sc->sc_state = state;
}

void carp_hmac_prepare(struct carp_softc *sc)
{
    unsigned char version = CARP_VERSION, type = CARP_ADVERTISEMENT;
    unsigned char vhid = sc->sc_vhid & 0xff;
    size_t i;
#ifdef INET6
    struct in6_addr in6;
#endif /* INET6 */
    
    /* compute ipad from key */
    memset(sc->sc_pad, 0, sizeof sc->sc_pad);
    memcpy(sc->sc_pad, sc->sc_key, sizeof sc->sc_key);
    for (i = 0; i < sizeof sc->sc_pad; i++) {
        sc->sc_pad[i] ^= 0x36;
    }    
    /* precompute first part of inner hash */
    SHA1Init(&sc->sc_sha1);
    SHA1Update(&sc->sc_sha1, sc->sc_pad, sizeof sc->sc_pad);
    SHA1Update(&sc->sc_sha1, (void *) &version, sizeof version);
    SHA1Update(&sc->sc_sha1, (void *) &type, sizeof type);
    SHA1Update(&sc->sc_sha1, (void *) &vhid, sizeof vhid);
    SHA1Update(&sc->sc_sha1, (void *) &vaddr.s_addr, sizeof vaddr.s_addr);
    
    /* convert ipad to opad */
    for (i = 0; i < sizeof sc->sc_pad; i++) {
        sc->sc_pad[i] ^= 0x36 ^ 0x5c;
    }
}

static unsigned short cksum(const void * const buf_, const size_t len)
{
    const unsigned char *buf = (unsigned char *) buf_;
    unsigned long sum = 0UL;
    size_t evenlen = len & ~ (size_t) 1U;
    size_t i = (size_t) 0U;
    
    if (len <= (size_t) 0U) {
        return 0U;
    }
    do {
        sum += (buf[i] << 8) | buf[i + 1];
        if (sum > 0xffff) {
            sum &= 0xffff;
            sum++;
        }
        i += 2;
    } while (i < evenlen);
    if (i != evenlen) {
        sum += buf[i] << 8;
        if (sum > 0xffff) {
            sum &= 0xffff;
            sum++;
        }
    }    
    return (unsigned short) ~sum;
}

static void carp_hmac_generate(struct carp_softc *sc, u_int32_t counter[2],
                               unsigned char *md)
{
    SHA1_CTX ctx;
    
    /* fetch first half of inner hash */
    memcpy(&ctx, &sc->sc_sha1, sizeof ctx);

    SHA1Update(&ctx, (void *) counter, sizeof sc->sc_counter);

    SHA1Final(md, &ctx);

    /* outer hash */
    SHA1Init(&ctx);
    SHA1Update(&ctx, sc->sc_pad, sizeof sc->sc_pad);
    SHA1Update(&ctx, md, 20);
    SHA1Final(md, &ctx);    
}

int carp_prepare_ad(struct carp_header *ch, struct carp_softc *sc)
{
    if (sc->sc_init_counter != 0) {
        /* this could also be seconds since unix epoch */
#ifdef HAVE_ARC4RANDOM
        sc->sc_counter = arc4random();        
#else
        sc->sc_counter = random();        
#endif
        sc->sc_counter <<= 32;
#ifdef HAVE_ARC4RANDOM        
        sc->sc_counter += arc4random();
#else
        sc->sc_counter += random();
#endif
    } else if (sc->sc_counter == 0xffffffffffffffffULL) {
        sc->sc_counter = 0ULL;
    } else {
        sc->sc_counter++;
    }    
    ch->carp_counter[0] = htonl((sc->sc_counter >> 32) & 0xffffffff);
    ch->carp_counter[1] = htonl(sc->sc_counter & 0xffffffff);

    carp_hmac_generate(sc, ch->carp_counter, ch->carp_md);
    
    return 0;
}

static void carp_send_ad(struct carp_softc *sc)
{
    struct carp_header ch;
    struct ether_header eh;
    struct timeval tv;
    struct ip ip;
    unsigned char *ip_ptr;
    unsigned char *pkt;
    unsigned short sum;    
    size_t ip_len;
    size_t eth_len;
    int advbase;
    int advskew;
    int rc;

#ifdef DEBUG
    logfile(LOG_DEBUG, "-> carp_send_ad()");
#endif
    advbase = sc->sc_advbase;
    if (carp_suppress_preempt == 0 ||
        sc->sc_advskew > CARP_BULK_UPDATE_MIN_DELAY) {
        advskew = sc->sc_advskew;
    } else {
        advskew = CARP_BULK_UPDATE_MIN_DELAY;
    }    
    if (yielding) {
        /* final advertisement before exiting, see carp_shutdown() */
        advbase = 255;
        advskew = 255;
    }
    tv.tv_sec = advbase;
    tv.tv_usec = (unsigned int) (advskew * 1000000ULL / 256ULL);

    ch.carp_version = CARP_VERSION;
    ch.carp_type = CARP_ADVERTISEMENT;
    ch.carp_vhid = sc->sc_vhid;
    ch.carp_advbase = advbase;
    ch.carp_advskew = advskew;
    ch.carp_authlen = CARP_AUTHLEN;
    ch.carp_pad1 = 0;   /* must be zero */
    ch.carp_cksum = 0;

    ip_len = sizeof ip + sizeof ch;
    eth_len = ip_len + sizeof eh;
    if ((pkt = ALLOCA(eth_len)) == NULL) {
        logfile(LOG_ERR, _("Out of memory to create packet"));
        sc->sc_ad_tmo.tv_sec = now.tv_sec + tv.tv_sec;
        sc->sc_ad_tmo.tv_usec = now.tv_usec + tv.tv_usec;            
        return;
    }
    ip.ip_v = IPVERSION;
    ip.ip_hl = (sizeof ip) >> 2;
    ip.ip_tos = IPTOS_LOWDELAY;
    ip.ip_len = htons(ip_len);
#ifdef HAVE_ARC4RANDOM
    ip.ip_id = htons(arc4random() & 0xffff);
#else
    ip.ip_id = htons(random() & 0xffff);
#endif
    ip.ip_off = htons(IP_DF);
    ip.ip_ttl = CARP_DFLTTL;
    ip.ip_p = IPPROTO_CARP;
    ip.ip_sum = 0;
    
    memcpy(&ip.ip_src, &srcip, sizeof ip.ip_src);    
    memcpy(&ip.ip_dst.s_addr, inaddr_carp_group, sizeof ip.ip_dst.s_addr);
    
    carp_prepare_ad(&ch, sc);       
    
    ch.carp_cksum = 0;
    sum = cksum(&ch, sizeof ch);
    ch.carp_cksum = htons(sum);    
    
    if (no_spoof) {
        /*
         * --nospoof: use the real NIC MAC as the advertisement source.
         * Needed where forged source MACs are dropped: VMware "Forged
         * transmits", Hyper-V MAC spoofing protection, switch port security.
         */
        memcpy(eh.ether_shost, hwaddr, sizeof hwaddr);
    } else {
        eh.ether_shost[0] = 0x00;
        eh.ether_shost[1] = 0x00;
        eh.ether_shost[2] = 0x5e;
        /*
         * Source MAC 00:00:5e:00:01:<vhid>, per RFC 7042 section 2.1.1
         * (https://www.rfc-editor.org/rfc/rfc7042.html):
         *   00-00-5E-00-00-00 .. 00-00-5E-00-00-FF: reserved, assignment
         *       requires IESG ratification (used by the original code);
         *   00-00-5E-00-01-00 .. 00-00-5E-00-01-FF: assigned to IPv4 VRRP
         *       [RFC 5798] (used here);
         *   00-00-5E-00-02-00 .. 00-00-5E-00-02-FF: assigned to IPv6 VRRP.
         * Note: a router running real VRRP on the same segment with a VRID
         * equal to this vhid uses the same MAC. Pick another vhid or use
         * --nospoof in that case.
         */
        eh.ether_shost[3] = 0x00;
        eh.ether_shost[4] = 0x01;
        eh.ether_shost[5] = vhid;
    }
    
    if (no_mcast) {
        eh.ether_dhost[0] = 0xff;
        eh.ether_dhost[1] = 0xff;
        eh.ether_dhost[2] = 0xff;
        eh.ether_dhost[3] = 0xff;
        eh.ether_dhost[4] = 0xff;
        eh.ether_dhost[5] = 0xff;        
    } else {
        eh.ether_dhost[0] = 0x01;
        eh.ether_dhost[1] = 0x00;
        eh.ether_dhost[2] = 0x5e;
        /* multicast MAC = 01:00:5e + low 23 bits of the group (RFC 1112) */
        eh.ether_dhost[3] = inaddr_carp_group[1] & 0x7f;
        eh.ether_dhost[4] = inaddr_carp_group[2];
        eh.ether_dhost[5] = inaddr_carp_group[3];        
    }    
    eh.ether_type = htons(ETHERTYPE_IP);    
    
    memcpy(pkt, &eh, sizeof eh);
    memcpy(pkt + sizeof eh, &ip, sizeof ip);
    memcpy(pkt + sizeof ip + sizeof eh, &ch, sizeof ch);

    ip_ptr = pkt + sizeof eh;
    sum = cksum(ip_ptr, ip_len);
    ip_ptr[offsetof(struct ip, ip_sum)] = (sum >> 8) & 0xff;
    ip_ptr[offsetof(struct ip, ip_sum) + 1] = sum & 0xff;

    do {
        rc = write(dev_desc_fd, pkt, eth_len);
    } while (rc < 0 && errno == EINTR);
    if (rc < 0) {
        cstats.adv_send_errors++;
        logfile(LOG_WARNING, _("write() has failed: %s"), strerror(errno));
        if (sc->sc_sendad_errors < INT_MAX) {
            sc->sc_sendad_errors++;
        }
        if (sc->sc_sendad_errors == CARP_SENDAD_MAX_ERRORS) {
#ifdef DEBUG
            logfile(LOG_ERR, _("write() error #%d/%d"),
                    carp_suppress_preempt, CARP_SENDAD_MAX_ERRORS);
#endif            
            carp_suppress_preempt++;
            if (carp_suppress_preempt == 1) {
                carp_send_ad_all(sc);
            }
        }
        sc->sc_sendad_success = 0;
    } else {
        cstats.adv_sent++;
        if (sc->sc_sendad_errors >= CARP_SENDAD_MAX_ERRORS) {
            if (++sc->sc_sendad_success >= CARP_SENDAD_MIN_SUCCESS) {
                carp_suppress_preempt--;
                sc->sc_sendad_errors = 0;
            }
        } else {
            sc->sc_sendad_errors = 0;
        }
    }
    
#ifdef DEBUG
    logfile(LOG_DEBUG, _("* advertisement injected *"));
#endif
    
    ALLOCA_FREE(pkt);
    
    if (sc->sc_delayed_arp > 0)
        sc->sc_delayed_arp--;
    if (sc->sc_delayed_arp == 0) {
        if (sc->sc_state == MASTER) {
            gratuitous_arp(dev_desc_fd);
        }
        sc->sc_delayed_arp = -1;
    }    
    if (advbase != 255 || advskew != 255) {
        sc->sc_ad_tmo.tv_sec = now.tv_sec + tv.tv_sec;
        sc->sc_ad_tmo.tv_usec = now.tv_usec + tv.tv_usec;            
        /* IPv6 ? */        
    }
}

static void carp_send_ad_all(struct carp_softc *sc) {
    carp_send_ad(sc);
}

static void carp_setrun(struct carp_softc *sc, sa_family_t af)
{
    struct timeval tv;    
    
#ifdef DEBUG
    logfile(LOG_DEBUG, "carp_setrun()");
#endif
    if (gettimeofday(&now, NULL) != 0) {
        logfile(LOG_WARNING, _("initializing now to gettimeofday() failed: %s"),
                strerror(errno));
    }
    switch (sc->sc_state) {
    case INIT:
        CARP_REASON("startup", 0U);
        carp_set_state(sc, BACKUP);
        carp_setrun(sc, 0);         
        break;
    case BACKUP:
        sc->sc_ad_tmo.tv_sec = 0;
        tv.tv_sec = (unsigned int) sc->sc_advbase * dead_ratio;
        tv.tv_usec = (unsigned int) (sc->sc_advskew * 1000000ULL / 256ULL);
        switch (af) {        
        case AF_INET:
            sc->sc_md_tmo.tv_sec = now.tv_sec + tv.tv_sec;
            sc->sc_md_tmo.tv_usec = now.tv_usec + tv.tv_usec;            
            break;
#ifdef INET6
        case AF_INET6:
            sc->sc_md6_tmo.tv_sec = now.tv_sec + tv.tv_sec;
            sc->sc_md6_tmo.tv_usec = now.tv_usec + tv.tv_usec;            
            break;
#endif /* INET6 */
        default:
            sc->sc_md_tmo.tv_sec = now.tv_sec + tv.tv_sec;
            sc->sc_md_tmo.tv_usec = now.tv_usec + tv.tv_usec;
#ifdef INET6
            sc->sc_md6_tmo.tv_sec = now.tv_sec + tv.tv_sec;
            sc->sc_md6_tmo.tv_usec = now.tv_usec + tv.tv_usec;
#endif
            break;
        }        
        break;
    case MASTER:
        tv.tv_sec = (unsigned int) sc->sc_advbase;
        tv.tv_usec = (unsigned int) (sc->sc_advskew * 1000000ULL / 256ULL);
        sc->sc_md_tmo.tv_sec = now.tv_sec + tv.tv_sec;
        sc->sc_md_tmo.tv_usec = now.tv_usec + tv.tv_usec;
        /* No IPv6 scheduling ? */
        break;
    }
}

static void carp_master_down(struct carp_softc *sc)
{
#ifdef DEBUG
    logfile(LOG_DEBUG, "carp_master_down()");
#endif
    switch (sc->sc_state) {
    case INIT:
#ifdef DEBUG
        logfile(LOG_DEBUG, _("master_down event in INIT state"));
#endif
        break;
    case MASTER:
        break;
    case BACKUP:
        if (maint_mode) {
            /*
             * Maintenance mode: never take over. This is the only path
             * from BACKUP to MASTER (timeout, preemption, "master").
             * Disarm the master-down timer so it doesn't fire again;
             * "maint off" or the next advertisement re-arms it.
             */
            sc->sc_md_tmo.tv_sec = 0;
            sc->sc_md_tmo.tv_usec = 0;
            break;
        }
        carp_set_state(sc, MASTER);
        carp_send_ad(sc);
        /* Schedule a delayed ARP request to deal w/ some L3 switches */
        sc->sc_delayed_arp = 2;
#ifdef INET6
        carp_send_na(sc);
#endif /* INET6 */
        carp_setrun(sc, 0);
        break;
    }    
}

static void packethandler(unsigned char *dummy,
                          const struct pcap_pkthdr *header,
                          const unsigned char *sp)
{
    struct ether_header etherhead;
    struct ip iphead;
    unsigned int source;
    unsigned int dest;
    unsigned char proto;
    unsigned int caplen;
    unsigned int ip_len;
            
    (void) dummy;
    if (header->caplen <= (sizeof etherhead + sizeof iphead)) {
        return;
    }    
    memcpy(&etherhead, sp, sizeof etherhead);
#ifdef DEBUG
    logfile(LOG_DEBUG, "Ethernet "
             "[%02x:%02x:%02x:%02x:%02x:%02x]->[%02x:%02x:%02x:%02x:%02x:%02x] "
             "type [%04x]",
            (unsigned int) etherhead.ether_shost[0],
            (unsigned int) etherhead.ether_shost[1],
            (unsigned int) etherhead.ether_shost[2],
            (unsigned int) etherhead.ether_shost[3],
            (unsigned int) etherhead.ether_shost[4],
            (unsigned int) etherhead.ether_shost[5],
            (unsigned int) etherhead.ether_dhost[0],
            (unsigned int) etherhead.ether_dhost[1],
            (unsigned int) etherhead.ether_dhost[2],
            (unsigned int) etherhead.ether_dhost[3],
            (unsigned int) etherhead.ether_dhost[4],
            (unsigned int) etherhead.ether_dhost[5],
            (unsigned int) ntohs(etherhead.ether_type));
#endif
    sp += sizeof etherhead;
    caplen = header->caplen - sizeof etherhead;
    memcpy(&iphead, sp, sizeof iphead);    
    if (iphead.ip_src.s_addr == srcip.s_addr) {
        return;
    }
    /* multicast mode: only accept advertisements sent to our group */
    if (!no_mcast && memcmp(&iphead.ip_dst.s_addr, inaddr_carp_group,
                            sizeof iphead.ip_dst.s_addr) != 0) {
        return;
    }
    ip_len = iphead.ip_hl << 2;
    source = ntohl(iphead.ip_src.s_addr);
    dest = ntohl(iphead.ip_dst.s_addr);
    proto = iphead.ip_p;
    switch (proto) {
    case IPPROTO_CARP: {
        struct carp_header ch;
        unsigned long long tmp_counter;
        struct timeval sc_tv;
        struct timeval ch_tv;        

#ifdef DEBUG
        logfile(LOG_DEBUG,
                "\n---------------------------\n\n"
                "carp [%d.%d.%d.%d] -> [%d.%d.%d.%d]",
                source >> 24 & 0xff, source >> 16 & 0xff,
                source >> 8 & 0xff, source & 0xff,
                dest >> 24 & 0xff, dest >> 16 & 0xff,
                dest >> 8 & 0xff, dest & 0xff);
#endif
        if (caplen < ip_len + sizeof ch) {
#ifdef DEBUG
            logfile(LOG_DEBUG,
                    "Bogus size: caplen=[%u], ip_len=[%u] ch_len=[%u]",
                    (unsigned int) caplen, (unsigned int) ip_len,
                    (unsigned int) sizeof ch);
#endif
            return;
        }
        memcpy(&ch, sp + ip_len, sizeof ch);
#ifdef EXTRA_DEBUG
        logfile(LOG_DEBUG,
                "Capture len: [%u] carp_header: [%u] ip_header: [%u]",
                (unsigned int) caplen, (unsigned int) sizeof ch,
                (unsigned int) ip_len);
        logfile(LOG_DEBUG, "CARP type: [%u] version: [%u]",
                (unsigned) ch.carp_type, (unsigned) ch.carp_version);
        logfile(LOG_DEBUG, "CARP vhid: [%u] advskew: [%u]",
                (unsigned) ch.carp_vhid, (unsigned) ch.carp_advskew);
        logfile(LOG_DEBUG, "CARP advbase: [%u] cksum: [%u]",
                (unsigned) ch.carp_advbase, (unsigned) ch.carp_cksum);
        logfile(LOG_DEBUG, "CARP counter: [%lu][%lu]",
                (unsigned long) ch.carp_counter[0],
                (unsigned long) ch.carp_counter[1]);
#endif
        if (iphead.ip_ttl != CARP_DFLTTL) {
            cstats.bad_ttl++;
            logfile(LOG_WARNING, _("Bad TTL: [%u]"),                    
                    (unsigned int) iphead.ip_ttl);
            return;
        }        
        if (ch.carp_version != CARP_VERSION) {
            cstats.bad_version++;
            logfile(LOG_WARNING, _("Bad version: [%u]"),
                    (unsigned int) ch.carp_version);
            return;
        }
        if (ch.carp_vhid != vhid) {
            cstats.other_vhid++;
#ifdef DEBUG
            logfile(LOG_NOTICE, _("Ignoring vhid: [%u]"),
                    (unsigned int) ch.carp_vhid);
#endif
            return;            
        }
        if (cksum(sp, ip_len + sizeof ch) != 0) {
            cstats.bad_cksum++;
            logfile(LOG_WARNING, _("Bad IP checksum"));
            return;
        }        
        {
            SHA1_CTX ctx;
            unsigned char md2[20];            
     
            memcpy(&ctx, &sc.sc_sha1, sizeof ctx);
            SHA1Update(&ctx, 
                       (void *) &ch.carp_counter, sizeof ch.carp_counter);
            SHA1Final(md2, &ctx);
            
            SHA1Init(&ctx);
            SHA1Update(&ctx, sc.sc_pad, sizeof(sc.sc_pad));
            SHA1Update(&ctx, md2, sizeof md2);
            SHA1Final(md2, &ctx);
            
            if (sizeof md2 != sizeof ch.carp_md) {
                logfile(LOG_ERR, "sizeof md2 != sizeof carp_md !!!");
                abort();
            }
            if (memcmp(md2, ch.carp_md, sizeof md2) != 0) {
                cstats.bad_auth++;
                cstats.last_bad_auth_src = iphead.ip_src;
                cstats.last_bad_auth_time = time(NULL);
                logfile(LOG_WARNING,
                        _("Bad digest - "
                          "md2=[%02x%02x%02x%02x...] md=[%02x%02x%02x%02x...] - "
                          "Check vhid, password and virtual IP address"),
                        (unsigned int) md2[0], (unsigned int) md2[1],
                        (unsigned int) md2[2], (unsigned int) md2[3],
                        (unsigned int) (ch.carp_md)[0],
                        (unsigned int) (ch.carp_md)[1],
                        (unsigned int) (ch.carp_md)[2],
                        (unsigned int) (ch.carp_md)[3]);
                return;
            }
        }
        /* authenticated advertisement: remember who sent it */
        cstats.adv_recv++;
        cstats.peer_valid = 1;
        cstats.peer = iphead.ip_src;
        cstats.peer_advbase = (unsigned int) ch.carp_advbase;
        cstats.peer_advskew = (unsigned int) ch.carp_advskew;
        (void) gettimeofday(&cstats.peer_last, NULL);

        tmp_counter = ntohl(ch.carp_counter[0]);
        tmp_counter = tmp_counter << 32;
        tmp_counter += ntohl(ch.carp_counter[1]);
        sc.sc_init_counter = 0;
        sc.sc_counter = tmp_counter;
        
        sc_tv.tv_sec = (unsigned int) sc.sc_advbase;
        if (carp_suppress_preempt != 0 &&
            sc.sc_advskew < CARP_BULK_UPDATE_MIN_DELAY) {
            sc_tv.tv_usec = (unsigned int)
                (CARP_BULK_UPDATE_MIN_DELAY * 1000000ULL / 256ULL);
        } else {
            sc_tv.tv_usec = (unsigned int)
                (sc.sc_advskew * 1000000ULL / 256ULL);
        }
        ch_tv.tv_sec = (unsigned int) ch.carp_advbase;
        ch_tv.tv_usec = (unsigned int)
            (ch.carp_advskew * 1000000ULL / 256ULL);
        
#ifdef DEBUG
        logfile(LOG_DEBUG, "sc_tv(local) = [%lu] ch_tv(remote) = [%lu]",
                (unsigned long) sc_tv.tv_sec,
                (unsigned long) ch_tv.tv_sec);
#endif
        
        switch (sc.sc_state) {
        case INIT:
                break;
        case MASTER:
            /*
             * If we receive an advertisement from a master who's going to
             * be more frequent than us, or from a master who's advertising
             * with the same frequency as us but with a lower IP address, 
             * go into BACKUP state.
             */
            if (timercmp(&sc_tv, &ch_tv, >) ||
                (timercmp(&sc_tv, &ch_tv, ==) &&
                 iphead.ip_src.s_addr < srcip.s_addr)) {
        /* To be really sure the new master knows that is
         * has to reassert control of the VIP */
        carp_send_ad(&sc);
        
                CARP_REASON("preferred_master", iphead.ip_src.s_addr);
                carp_set_state(&sc, BACKUP);
                carp_setrun(&sc, 0);
                logfile(LOG_WARNING, _("Preferred master advertised: "
                                       "going back to BACKUP state"));
            }

            /*
             * If we receive an advertisement from a master who's advertising
             * less frequently than us, or with the same frequency as us but
             * with a higher IP address, reassert our dominance by issuing
             * another gratuitous arp.
             */
            if (timercmp(&sc_tv, &ch_tv, <) ||
                (timercmp(&sc_tv, &ch_tv, ==) &&
         iphead.ip_src.s_addr > srcip.s_addr)) {
        gratuitous_arp(dev_desc_fd);
        sc.sc_delayed_arp = 2; /* and yet another in 2 ticks */
        logfile(LOG_WARNING, _("Non-preferred master advertising: "
                       "reasserting control of VIP with another gratuitous arp"));
            }
        break;
        case BACKUP:
            /*
             * If we're pre-empting masters who advertise slower than us,
             * and this one claims to be slower, treat him as down.
             */
            if (preempt != 0 && timercmp(&sc_tv, &ch_tv, <)) {
                CARP_REASON("preempt", iphead.ip_src.s_addr);
                carp_master_down(&sc);
                logfile(LOG_WARNING, _("Putting MASTER down - preemption"));
                break;
            }
            
            /*
             *  If the master is going to advertise at such a low frequency
             *  that he's guaranteed to time out, we'd might as well just
             *  treat him as timed out now.
             */
            sc_tv.tv_sec = (unsigned int) sc.sc_advbase * dead_ratio;
            if (timercmp(&sc_tv, &ch_tv, <)) {
                CARP_REASON("master_will_time_out", iphead.ip_src.s_addr);
                carp_master_down(&sc);
                logfile(LOG_WARNING, 
                        _("Putting MASTER DOWN (going to time out)"));
                break;
            }
            
            /*
             * Otherwise, we reset the counter and wait for the next
             * advertisement.
             */
            carp_setrun(&sc, AF_INET); /* XXX - TODO was af */
            break;
        }
        break;
    }
    default:
        return;
    }
}     

/*
 * Control port "master": become MASTER now.
 * One-shot change, the role is not locked; normal election continues.
 * Returns CTRL_OK, CTRL_ERR_IFDOWN, CTRL_ERR_HOLD or CTRL_ERR_MAINT.
 */
int carp_control_master(void)
{
    if (maint_mode) {
        return CTRL_ERR_MAINT;  /* "maint off" first */
    }
    if (!iface_running) {
        return CTRL_ERR_IFDOWN; /* would be undone by the down handling */
    }
    if (ctrl_holding) {
        return CTRL_ERR_HOLD;   /* no adverts during the hold: VIP gap */
    }
    if (sc.sc_state == MASTER) {
        return 0;
    }
    CARP_REASON("ctrl_master", 0U);
    if (sc.sc_state == INIT) {
        /* carp_master_down() only handles BACKUP -> MASTER */
        carp_set_state(&sc, BACKUP);
    }
    carp_master_down(&sc);
    return 0;
}

/*
 * Control port "backup": become BACKUP now and run the downscript.
 * Not locked either: if no other master advertises, we take over again
 * when the master-down timer expires. Use "maint on" to stay BACKUP.
 */
int carp_control_backup(void)
{
    if (sc.sc_state == BACKUP) {
        return 0;
    }
    CARP_REASON("ctrl_backup", 0U);
    carp_set_state(&sc, BACKUP);
    sc.sc_delayed_arp = 0;
    /* stop sending MASTER adverts and restart the master-down timer */
    sc.sc_ad_tmo.tv_sec = 0;
    sc.sc_ad_tmo.tv_usec = 0;
    carp_setrun(&sc, 0);
    return 0;
}

/*
 * Control port "maint on" / "maint off".
 * on : become BACKUP now (downscript runs if we were MASTER) and refuse
 *      every promotion until switched off. We keep listening, so the
 *      state reply still shows the current master as peer.
 * off: resume normal election; with no master around we take over after
 *      advbase*deadratio, as after startup.
 */
int carp_control_maint(const int on)
{
    if (on) {
        if (maint_mode) {
            return CTRL_OK;
        }
        maint_mode = 1;
        maint_since = time(NULL);
        logfile(LOG_WARNING, _("Maintenance mode on: staying BACKUP"));
        if (sc.sc_state != BACKUP) {
            CARP_REASON("maint_on", 0U);
            carp_set_state(&sc, BACKUP);
            sc.sc_delayed_arp = 0;
            sc.sc_ad_tmo.tv_sec = 0;
            sc.sc_ad_tmo.tv_usec = 0;
        }
        sc.sc_md_tmo.tv_sec = 0;
        sc.sc_md_tmo.tv_usec = 0;
        return CTRL_OK;
    }
    if (!maint_mode) {
        return CTRL_OK;
    }
    maint_mode = 0;
    maint_since = 0;
    logfile(LOG_WARNING, _("Maintenance mode off: resuming election"));
    if (iface_running && !ctrl_holding) {
        carp_setrun(&sc, 0);    /* re-arm the master-down timer */
    }
    return CTRL_OK;
}

int carp_maint(void)
{
    return maint_mode;
}

time_t carp_maint_since(void)
{
    return maint_since;
}

/*
 * Graceful exit (-z), called from the main loop after SIGINT/SIGQUIT/
 * SIGTERM.
 *
 * As MASTER, run the downscript first, so the VIP is never configured on
 * two hosts, then send one advertisement with advbase=255 and
 * advskew=255. A backup sees a master that is going to time out and takes
 * over at once ("Putting MASTER DOWN (going to time out)") instead of
 * after advbase*deadratio. This is what OpenBSD carp sends when going
 * down, and unmodified ucarp peers handle it the same way; the backup
 * does not need -P.
 */
static void carp_shutdown(const int sig)
{
    logfile(LOG_WARNING, _("Signal %d received: exiting as %s"),
            sig, carp_state_str((int) sc.sc_state));
    if (sc.sc_state != BACKUP) {
        (void) spawn_handler(dev_desc_fd, downscript);
    }
    if (sc.sc_state == MASTER) {
        /* no delayed gratuitous ARP for the VIP we have just removed */
        sc.sc_delayed_arp = -1;
        yielding = 1;
        (void) gettimeofday(&now, NULL);
        carp_send_ad(&sc);
        logfile(LOG_WARNING, _("Final advertisement sent "
                               "(advbase=255 advskew=255): "
                               "the backup takes over now"));
    }
    _exit(EXIT_SUCCESS);
}

/* -z only: just record the signal, carp_shutdown() does the work */
RETSIGTYPE sighandler_exit(const int sig)
{
    exit_signal = sig;
}

RETSIGTYPE sighandler_usr(const int sig)
{
    switch (sig) {
    case SIGUSR1:
    received_signal=1;
    break;
    case SIGUSR2:
    received_signal=2;
    break;
    }
}

char *build_bpf_rule(void)
{
    static char rule[256];
    const char *srcip_s;    
    
    if ((srcip_s = inet_ntoa(srcip)) == NULL) {
        logfile(LOG_ERR, "inet_ntoa: [%s]", strerror(errno));
        return NULL;
    }
    /* multicast mode: also match the destination group */
    if (no_mcast) {
        snprintf(rule, sizeof rule, "proto %u and src host not %s",
                 (unsigned int) IPPROTO_CARP, srcip_s);
    } else {
        snprintf(rule, sizeof rule,
                 "proto %u and src host not %s and dst host %u.%u.%u.%u",
                 (unsigned int) IPPROTO_CARP, srcip_s,
                 (unsigned int) inaddr_carp_group[0],
                 (unsigned int) inaddr_carp_group[1],
                 (unsigned int) inaddr_carp_group[2],
                 (unsigned int) inaddr_carp_group[3]);
    }
#ifdef DEBUG
    logfile(LOG_DEBUG, "BPF rule: [%s]", rule);
#endif
    
    return rule;
}

int docarp(void)
{
    char errbuf[PCAP_ERRBUF_SIZE];
    struct ip_mreq req_add;   
    struct bpf_program bpfp;
    struct pollfd pfds[1 + CTRL_MAX_POLLFDS];   /* [0] pcap, rest: ctrl */
    int npfds;
    struct ifreq iface;
    int fd;
    int nfds;
    int poll_sleep_time;
    struct timeval time_until_advert;

    sc.sc_vhid = vhid;
    sc.sc_advbase = advbase;
    sc.sc_advskew = advskew;
    sc.sc_init_counter = 1;
    sc.sc_delayed_arp = -1;
#ifdef INET6
    sc.sc_im6o.im6o_multicast_hlim = CARP_DFLTTL;
#endif /* INET6 */
    cstats.started = time(NULL);
    carp_set_state(&sc, INIT);
    {
        const size_t passlen = strlen(pass) + (size_t) 1U;
        
        if (passlen > sizeof sc.sc_key) {
            logfile(LOG_ERR, _("Password too long"));
            return -1;
        }
        memcpy(sc.sc_key, pass, passlen);
    }
    sc.sc_ad_tmo.tv_sec = 0;
    sc.sc_ad_tmo.tv_usec = 0;    
    sc.sc_md_tmo.tv_sec = 0;
    sc.sc_md6_tmo.tv_usec = 0;    
    
    carp_hmac_prepare(&sc);

    if (fill_mac_address() != 0) {
        logfile(LOG_ERR, _("Unable to find MAC address of [%s]"),
                interface == NULL ? "-" : interface);
        return -1;
    }
    logfile(LOG_INFO, _("Local advertised ethernet address is "
                        "[%02x:%02x:%02x:%02x:%02x:%02x]"),
            (unsigned int) hwaddr[0], (unsigned int) hwaddr[1],
            (unsigned int) hwaddr[2], (unsigned int) hwaddr[3],
            (unsigned int) hwaddr[4], (unsigned int) hwaddr[5]);
    if ((dev_desc = pcap_open_live(interface, ETHERNET_MTU, 0,
                                   CAPTURE_TIMEOUT, errbuf)) == NULL) {
        logfile(LOG_ERR, _("Unable to open interface [%s]: %s"),
                interface == NULL ? "-" : interface, errbuf);
        return -1;
    }    
    if (pcap_compile(dev_desc, &bpfp, build_bpf_rule(),
                     1, (bpf_u_int32) 0) != 0) {
        logfile(LOG_ERR, _("Unable to compile pcap rule: %s [%s]"),
                errbuf, interface == NULL ? "-" : interface);
        return -1;
    }
    pcap_setfilter(dev_desc, &bpfp);
    dev_desc_fd = pcap_fileno(dev_desc);
    pfds[0].fd = dev_desc_fd;
    pfds[0].events = POLLIN | POLLERR | POLLHUP;
    
    if (shutdown_at_exit != 0) {
        (void) signal(SIGINT, sighandler_exit);
        (void) signal(SIGQUIT, sighandler_exit);
        (void) signal(SIGTERM, sighandler_exit);
    }
    (void) signal(SIGUSR1, sighandler_usr);
    (void) signal(SIGUSR2, sighandler_usr);
    /* start the control port (no-op without -c) */
    if (ctrl_init() != 0) {
        return -1;
    }

    if (gettimeofday(&now, NULL) != 0) {
        logfile(LOG_WARNING, _("initializing now to gettimeofday() failed: %s"),
                strerror(errno));
    }
    carp_setrun(&sc, 0); 
    
    if ((fd = socket(PF_INET, SOCK_DGRAM, 0)) == -1) {
        logfile(LOG_ERR, _("Error opening socket for interface [%s]: %s"),
                interface == NULL ? "-" : interface, strerror(errno));
        return -1;
    }
    if (!no_mcast) {
        memset(&req_add, 0, sizeof req_add);
        /* join the --mcast group (default 224.0.0.18) */
        memcpy(&req_add.imr_multiaddr.s_addr, inaddr_carp_group,
               sizeof req_add.imr_multiaddr.s_addr);
        req_add.imr_interface.s_addr = srcip.s_addr;
        if (setsockopt(fd, IPPROTO_IP, IP_ADD_MEMBERSHIP,
                       &req_add, sizeof req_add) < 0) {
            logfile(LOG_ERR, "Can't do IP_ADD_MEMBERSHIP errno=%s (%d)",
                    strerror(errno), errno);
            close(fd);
            return -1;
        }
    }
#ifdef SIOCGIFFLAGS    
    if (strlen(interface) >= sizeof iface.ifr_name) {
        logfile(LOG_ERR, _("Interface name too long"));
        return -1;
    }
    strncpy(iface.ifr_name, interface, sizeof iface.ifr_name);
#endif    
    for (;;) {
        if (exit_signal != 0) {
            carp_shutdown((int) exit_signal);
        }
#ifdef SIOCGIFFLAGS
        if (ioctl(fd, SIOCGIFFLAGS, &iface) != 0) {
            break;
        }
        if ((iface.ifr_flags & IFF_RUNNING) == 0) {
        if (ignoreifstate == 0) {
        CARP_REASON("interface_down", 0U);
        carp_set_state(&sc, BACKUP);
        sc.sc_ad_tmo.tv_sec = 0;
        sc.sc_ad_tmo.tv_usec = 0;
        sc.sc_md_tmo.tv_sec = 0;
        sc.sc_md6_tmo.tv_usec = 0;
            if (iface_running) {
            iface_running = 0;
        }
        /* was sleep(10): keep answering the control port while waiting */
        ctrl_serve_for(SECONDS_TO_WAIT_AFTER_INTERFACE_IS_DOWN * 1000U);
        continue;
        }
        } else {
            if (!iface_running) {
                iface_running = 1;
                carp_setrun(&sc, 0);
            }
        }
#endif
        if (received_signal != 0) {
            int flag = received_signal;
        
            received_signal = 0;
            switch (flag) {
        case 1:
        logfile(LOG_INFO, "%s on %s id %d", 
            (sc.sc_state == BACKUP ? "BACKUP" : "MASTER"),
            interface, sc.sc_vhid);
        break;
        case 2:
#ifdef DEBUG
        logfile(LOG_DEBUG, "Caught signal (USR2) considering going down");
#endif
        if (sc.sc_state != BACKUP) {
            CARP_REASON("sigusr2", 0U);
            carp_set_state(&sc, BACKUP);
            /* was sleep(3): hold for 3s but keep answering the control
             * port ("master" is refused meanwhile) */
            ctrl_holding = 1;
            ctrl_serve_for(3000U);
            ctrl_holding = 0;
            carp_setrun(&sc, 0); /* now listen for 3 heartbeats, as usual */
            continue;
        }
        break;
            }
        }

        if (sc.sc_ad_tmo.tv_sec == 0) {
            poll_sleep_time = sc.sc_advbase * 1000;
        } else {
            if (gettimeofday(&now, NULL) != 0) {
                logfile(LOG_WARNING, _("gettimeofday() failed: %s"),
                        strerror(errno));
                continue;
            }
            timersub(&sc.sc_ad_tmo, &now, &time_until_advert);
            poll_sleep_time = (time_until_advert.tv_sec * 1000) +
                (time_until_advert.tv_usec / 1000);
        }
        /* pfds[0] is pcap; control port fds are appended after it */
        pfds[0].revents = 0;
        npfds = 1 + ctrl_fill_pollfds(&pfds[1]);
        /* shorten the wait to the nearest control client deadline */
        poll_sleep_time = ctrl_poll_timeout(poll_sleep_time);
        nfds = poll(pfds, (nfds_t) npfds, MAX(1, poll_sleep_time));
        if (nfds == -1) {
            if (errno == EINTR) {
               continue;
            }
            logfile(LOG_ERR, _("exiting: poll() error: %s"), strerror(errno));
        }
        if ((pfds[0].revents & (POLLERR | POLLHUP)) != 0) {
            logfile(LOG_ERR, _("exiting: pfds[0].revents = %d"),
                    pfds[0].revents);
            break;
        }
        if (gettimeofday(&now, NULL) != 0) {
            logfile(LOG_WARNING, _("gettimeofday() failed: %s"),
                    strerror(errno));
            continue;
        }        
        /* read pcap only if its fd is ready ("nfds == 1" no longer works) */
        if (nfds > 0 && (pfds[0].revents & POLLIN) != 0) {
            pcap_dispatch(dev_desc, 1, packethandler, NULL);
        }
        /* control port: accept, read commands, write replies, timeouts */
        if (nfds > 0) {
            ctrl_handle_pollfds(&pfds[1]);
        } else {
            ctrl_check_timeout();
        }
        if (sc.sc_md_tmo.tv_sec != 0 && timercmp(&now, &sc.sc_md_tmo, >)) {
            /* peer = the master we last heard from (none at startup) */
            CARP_REASON("master_down_timeout",
                        cstats.peer_valid ? cstats.peer.s_addr : 0U);
            carp_master_down(&sc);
        }
#ifdef INET6
        if (sc.sc_md6_tmo.tv_sec != 0 && timercmp(&now, &sc.sc_md6_tmo, >)) {
            CARP_REASON("master_down_timeout",
                        cstats.peer_valid ? cstats.peer.s_addr : 0U);
            carp_master_down(&sc);
        }
#endif
        if (sc.sc_ad_tmo.tv_sec != 0) {
           if (timercmp(&now, &sc.sc_ad_tmo, >)) {
                carp_send_ad(&sc);
           } else {
               timersub(&sc.sc_ad_tmo, &now, &time_until_advert);
               int diff_ms = (time_until_advert.tv_sec * 1000) +
                   (time_until_advert.tv_usec / 1000);
               if (abs(diff_ms) <= 1) {
                    carp_send_ad(&sc);
               }
           }
       }
    }
    pcap_close(dev_desc);
    pcap_freecode(&bpfp);
    
    return 0;
}
