
#define DEFINE_GLOBALS 1

#include <config.h>
#include "ucarp.h"
#ifndef HAVE_GETOPT_LONG
# include "bsd-getopt_long.h"
#else
# include <getopt.h>
#endif
#ifdef HAVE_SETLOCALE
# include <locale.h>
#endif
#include "log.h"
#include "daemonize.h"
#include "ucarp_p.h"

#ifdef WITH_DMALLOC
# include <dmalloc.h>
#endif

static void usage(void)
{
    puts("\n" PACKAGE_STRING " - " __DATE__ "\n");
    puts(PACKAGE_DEVELOPER "\n");
    fputs(_(
        "--interface=<if> (-i <if>): bind interface <if>\n"
        "--srcip=<ip> (-s <ip>): source (real) IP address of that host\n"
        "--vhid=<id> (-v <id>): virtual IP identifier (1-255)\n"
        "--pass=<pass> (-p <pass>): password\n"
        "--passfile=<file> (-o <file>): read password from file\n"
        "--preempt (-P): becomes a master as soon as possible\n"
        "--neutral (-n): don't run downscript at start if backup\n"
        "--addr=<ip> (-a <ip>): virtual shared IP address\n"
        "--help (-h): summary of command-line options\n"
        "--advbase=<seconds> (-b <seconds>): advertisement frequency\n"
        "--advskew=<skew> (-k <skew>): advertisement skew (0-255)\n"
        "--upscript=<file> (-u <file>): run <file> to become a master\n"
        "--downscript=<file> (-d <file>): run <file> to become a backup\n"
        "--deadratio=<ratio> (-r <ratio>): ratio to consider a host as dead\n"
        "--shutdown (-z): call shutdown script at exit\n"
        "--daemonize (-B): run in background\n"
        "--ignoreifstate (-S): ignore interface state (down, no carrier)\n"
        "--mcast=<ip> (-m <ip>): IPv4 multicast group (default 224.0.0.18)\n"
        "--scripttimeout=<sec> (-T <sec>): kill up/down script after <sec>\n"
        "    (default: advbase*deadratio-1, min 1; 0 = wait forever)\n"
        "--nomcast (-M): use broadcast (instead of multicast) advertisements\n"
        "--nospoof (-F): use the real interface MAC as source of advertisements\n"
        "--facility=<facility> (-f): set syslog facility (default=daemon)\n"
        "--xparam=<value> (-x): extra parameter to send to up/down scripts\n"
        "--ctrlport=<port> (-c <port>): control port on TCP 127.0.0.1 (cmd: state/master/backup)\n"       
        "\n"
        "Example:\n"
        "\n"
        "ucarp --interface=eth0 --srcip=10.1.1.1 --vhid=1 --pass=mypassword \\\n"
        "      --addr=10.1.1.252 --ctrlport=9000 \\\n"
        "      --upscript=/etc/vip-up.sh --downscript=/etc/vip-down.sh\n"
        "\n\n"    
        "Please report bugs to "), stdout);
    puts(PACKAGE_BUGREPORT ".\n");
    
    exit(EXIT_SUCCESS);
}

static void init_rand(void)
{
    struct timeval tv;
    
    gettimeofday(&tv, NULL);
#ifdef HAVE_SRANDOMDEV
    srandomdev();
#elif defined(HAVE_RANDOM)
    srandom((unsigned int) (tv.tv_sec ^ tv.tv_usec ^ (getpid() << 16)));
#else
    srand((unsigned int) (tv.tv_sec ^ tv.tv_usec ^ (getpid() << 16)));
#endif    
}

static void die_mem(void)
{
    logfile(LOG_ERR, _("Out of memory"));
    
    exit(EXIT_FAILURE);
}

int main(int argc, char *argv[])
{
    int option_index = 0;
    int fodder;
    int mcast_set = 0;
    int script_timeout_set = 0;
    
#ifdef HAVE_SETLOCALE
    setlocale(LC_ALL, "");
#endif
    bindtextdomain(PACKAGE, LOCALEDIR);
    textdomain(PACKAGE);
    
    if (argc <= 1) {
        usage();
    }        
    while ((fodder = getopt_long(argc, argv, GETOPT_OPTIONS, long_options,
                                 &option_index)) != -1) {
        switch (fodder) {
        case 'h': {
            usage();
        }
        case 'i': {
            free(interface);
            if ((interface = strdup(optarg)) == NULL) {
                die_mem();
            }
            break;            
        }
        case 's': {
            if (inet_pton(AF_INET, optarg, &srcip) == 0) {
                logfile(LOG_ERR, _("Invalid address: [%s]"), optarg);
                return 1;
            }
            break;            
        }
        case 'v': {
            vhid = (unsigned char) strtoul(optarg, NULL, 0);
            break;            
        }       
        case 'p': {
            free(pass);
            if ((pass = strdup(optarg)) == NULL) {
                die_mem();
            }
            break;            
        }
        case 'o': {
            char buf[512U];
            char *p;
            FILE *pw;
            if ((pw = fopen(optarg, "r")) == NULL) {
                logfile(LOG_ERR,
                        _("unable to open passfile %s for reading: %s"),
                        optarg, strerror(errno));
                return 1;
            }
            if (fgets(buf, sizeof buf, pw) == NULL) {
                logfile(LOG_ERR, _("error reading passfile %s: %s"), optarg,
                        ferror(pw) ?
                        strerror(errno) : _("unexpected end of file"));
                return 1;
            }
            fclose(pw);
            p = strchr(buf, '\n');
            if (p != NULL) {
                *p = 0;
            }
            if ((pass = strdup(buf)) == NULL) {
                die_mem();
            }
            break;
        }
        case 'P': {
            preempt = 1;
            break;
        }
        case 'n': {
            neutral = 1;
            break;
        }
        case 'a': {
            free(vaddr_arg);
            if (inet_pton(AF_INET, optarg, &vaddr) == 0) {
                logfile(LOG_ERR, _("Invalid address: [%s]"), optarg);
                return 1;
            }
            vaddr_arg = strdup(optarg);
            break;
        }
        case 'b': {
            advbase = (unsigned char) strtoul(optarg, NULL, 0);
            break;            
        }
        case 'k': {
            advskew = (unsigned char) strtoul(optarg, NULL, 0);            
            break;            
        }
        case 'd': {
            free(downscript);
            if ((downscript = strdup(optarg)) == NULL) {
                die_mem();
            }
            break;
        }
        case 'u': {
            free(upscript);
            if ((upscript = strdup(optarg)) == NULL) {
                die_mem();
            }
            break;
        }
        case 'r': {
            dead_ratio = (unsigned int) strtoul(optarg, NULL, 0);
            break;
        }
        case 'z': {
            shutdown_at_exit = 1;
            break;
        }
        case 'B': {
            daemonize = 1;
            break;
        }
        case 'S': {
            ignoreifstate = 1;
            break;
        }
        case 'f': {
            int n = 0;
            
            if (strcasecmp(optarg, "none") == 0) {
                no_syslog = 1;
                break;
            }
            while (facilitynames[n].c_name &&
                   strcasecmp(facilitynames[n].c_name, optarg) != 0) {
                n++;
            }
            if (facilitynames[n].c_name) {
                syslog_facility = facilitynames[n].c_val;
            } else {
                logfile(LOG_ERR, _("Unknown syslog facility: [%s]"), optarg);
            }
            break;
        }
        case 'x': {
            free(xparam);
            if ((xparam = strdup(optarg)) == NULL) {
                die_mem();
            }
            break;
        }
        case 'm': {
            struct in_addr group;
            unsigned long host;

            if (inet_pton(AF_INET, optarg, &group) != 1) {
                logfile(LOG_ERR, _("Invalid multicast address: [%s]"), optarg);
                return 1;
            }
            host = (unsigned long) ntohl(group.s_addr);
            if ((host & 0xf0000000UL) != 0xe0000000UL) {
                logfile(LOG_ERR, _("Not an IPv4 multicast address: [%s]"), optarg);
                return 1;
            }
            memcpy(inaddr_carp_group, &group.s_addr, sizeof group.s_addr);
            mcast_set = 1;
            break;
        }
        case 'T': {
            char *end;
            unsigned long t = strtoul(optarg, &end, 10);

            if (*optarg == 0 || *end != 0 || t > 3600UL) {
                logfile(LOG_ERR, _("Invalid script timeout: [%s]"), optarg);
                return 1;
            }
            script_timeout = (unsigned int) t;
            script_timeout_set = 1;
            break;
        }
        case 'F': {
            no_spoof = 1;
            break;
        }
        case 'M': {
            no_mcast = 1;
            break;
        }
        case 'c': {
            char *end;
            unsigned long p = strtoul(optarg, &end, 10);

            if (*optarg == 0 || *end != 0 || p == 0UL || p > 65535UL) {
                logfile(LOG_ERR, _("Invalid control port: [%s]"), optarg);
                return 1;
            }
            ctrl_port = (unsigned int) p;
            break;
        }
        default: {
            usage();
        }
        }
    }
#ifndef SAVE_DESCRIPTORS
    if (no_syslog == 0) {
        openlog("ucarp", LOG_PID, syslog_facility);
    }
#endif    
    if (interface == NULL || *interface == 0) {        
        interface = pcap_lookupdev(NULL);
        if (interface == NULL || *interface == 0) {
            logfile(LOG_ERR, _("You must supply a network interface"));
            return 1;
        }
        logfile(LOG_INFO, _("Using [%s] as a network interface"), interface);
    }
    if (vhid == 0) {
        logfile(LOG_ERR, _("You must supply a valid virtual host id"));
        return 1;
    }
    if (pass == NULL || *pass == 0) {
        logfile(LOG_ERR, _("You must supply a password"));
        return 1;
    }
    if (script_timeout_set == 0) {
        /* must finish before the peer declares us dead */
        unsigned int dead = (unsigned int) advbase * dead_ratio;

        script_timeout = dead > 1U ? dead - 1U : 1U;
    } else if (script_timeout != 0U &&
               script_timeout >= (unsigned int) advbase * dead_ratio) {
        logfile(LOG_WARNING, _("Script timeout %u >= advbase*deadratio (%u): "
                               "a stuck script can still cause a split brain"),
                script_timeout, (unsigned int) advbase * dead_ratio);
    }
    if (mcast_set && no_mcast) {
        logfile(LOG_ERR, _("--mcast and --nomcast cannot be used together"));
        return 1;
    }
    if (advbase == 0 && advskew == 0) {
        logfile(LOG_ERR, _("You must supply an advertisement time base"));
        return 1;
    }
    if (srcip.s_addr == 0) {
        logfile(LOG_ERR, _("You must supply a persistent source address"));
        return 1;
    }
    if (vaddr.s_addr == 0) {
        logfile(LOG_ERR, _("You must supply a virtual host address"));
        return 1;
    }
    if (upscript == NULL) {
        logfile(LOG_WARNING, _("Warning: no script called when going up"));
    }
    if (downscript == NULL) {
        logfile(LOG_WARNING, _("Warning: no script called when going down"));
    }
    if (dead_ratio <= 0U) {
        logfile(LOG_ERR, _("Dead ratio can't be zero"));
        return 1;
    }
    dodaemonize();
    init_rand();
    if (docarp() != 0) {
        return 2;
    }
    
#ifndef SAVE_DESCRIPTORS
    if (no_syslog == 0) {
        closelog();
    }
#endif    
    
    return 0;
}
