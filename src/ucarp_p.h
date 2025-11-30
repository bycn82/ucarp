#ifndef __CARP_P_H__
#define __CARP_P_H__ 1

static const char *GETOPT_OPTIONS = "i:s:v:p:Pa:hb:k:x:nu:d:r:zf:Bo:SMFc:m:T:K:";

static struct option long_options[] = {
    { "interface", 1, NULL, 'i' },
    { "srcip", 1, NULL, 's' },
    { "vhid", 1, NULL, 'v' },
    { "pass", 1, NULL, 'p' },
    { "preempt", 0, NULL, 'P' },
    { "neutral", 0, NULL, 'n' },
    { "addr", 1, NULL, 'a' },
    { "help", 0, NULL, 'h' },
    { "advbase", 1, NULL, 'b' },
    { "advskew", 1, NULL, 'k' },
    { "upscript", 1, NULL, 'u' },
    { "downscript", 1, NULL, 'd' },
    { "deadratio", 1, NULL, 'r' },
    { "shutdown", 0, NULL, 'z' },
    { "facility", 1, NULL, 'f' },
    { "daemonize", 0, NULL, 'B' },
    { "ignoreifstate", 0, NULL, 'S' },
    { "nomcast", 0, NULL, 'M' },
    { "nospoof", 0, NULL, 'F' },          /* new: real MAC in adverts */
    { "mcast", 1, NULL, 'm' },            /* new: multicast group */
    { "scripttimeout", 1, NULL, 'T' },    /* new: script timeout */
    { "passfile", 1, NULL, 'o' },
    { "xparam", 1, NULL, 'x' },
    { "ctrlport", 1, NULL, 'c' },         /* new: control port */
    { "ctrlkeyfile", 1, NULL, 'K' },      /* new: control key file */
    { NULL, 0, NULL, 0 }
};

#endif
