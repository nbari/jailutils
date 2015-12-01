/*
 * Copyright (c) 2004, Stef Walter
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *     * Redistributions of source code must retain the above
 *       copyright notice, this list of conditions and the
 *       following disclaimer.
 *     * Redistributions in binary form must reproduce the
 *       above copyright notice, this list of conditions and
 *       the following disclaimer in the documentation and/or
 *       other materials provided with the distribution.
 *     * The names of contributors to this software may not be
 *       used to endorse or promote products derived from this
 *       software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS
 * OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED
 * AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF
 * THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH
 * DAMAGE.
 *
 *
 * CONTRIBUTORS
 *  Stef Walter <stef@memberwebs.com>
 *
 */

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/param.h>
#include <sys/sysctl.h>
#include <sys/proc.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <sys/jail.h>

#include <paths.h>
#include <signal.h>
#include <stdio.h>
#include <syslog.h>
#include <err.h>
#include <errno.h>
#include <stdarg.h>
#include <unistd.h>
#include <kvm.h>
#include <limits.h>
#include <fcntl.h>
#include <string.h>
#include <stdlib.h>

#include "util.h"

#ifdef HAVE_CONFIG_H
#include "../config.h"
#endif

/* The timeout to wait between kills */
#define        DEFAULT_TIMEOUT        3
int g_timeout = DEFAULT_TIMEOUT;

int g_quiet = 0;        /* Supress warnings */
int g_verbose = 0;      /* Print output from scripts */
int g_force = 0;        /* Use SIGKILL after if processes don't exit */
int g_usescripts = 1;   /* Call startup and shutdown scripts */
int g_restart = 0;      /* Restart jail after stop */

static int kill_jail(const char* jail);
static void kill_jail_processes(kvm_t* kd, int sig);
static int check_running_processes(kvm_t* kd);

static void parse_jail_opts(int argc, char* argv[]);
static void parse_host_opts(int argc, char* argv[]);

static void usage();
static void usage_jail();
static void usage_hr(const char* name);

int main(int argc, char* argv[])
{
    struct xprison* xp = NULL;
    jails jls;
    size_t len;
    int jid, r, ret = 0;
    pid_t child;

    if(getuid() != 0)
        errx(1, "must run as root");

    /*
     * When running in a jail we do things slightly
     * differently, and accept different args
     */
    if(running_in_jail() != 0)
    {
        parse_jail_opts(argc, argv);

        /*
         * Turn into a daemon, so that we don't get disconnected
         * when we kill our parent program.
         */
        if(daemon(0, 1) == -1)
            err(1, "couldn't disconnect from console");

    	/* Ignore these signals as all sorts of crazy stuff happens around our process */
        ignore_signals ();

        r = kill_jail(argv[0]);
        exit(r);
    }

    else
    {
        parse_host_opts(argc, argv);

        argc -= optind;
        argv += optind;

        jails_load(&jls);

        /* For each jail */
        for(; argc > 0; argc--, argv++)
        {
            xp = jails_find(&jls, argv[0]);

            if(xp == NULL)
            {
                warnx("unknown jail host name: %s", argv[0]);
                ret = 1;
                continue;
            }

            /* This makes sure we can use kvm funcs in jail */
            kvm_prepare_jail(xp);

            /*
             * We fork and the child goes into the jail and
             * does the dirty work. Unless in debug mode where
             * we just do one jail.
              */
#ifdef _DEBUG
            switch((child = fork()))
            {
            /* Error condition */
            case -1:
                err(1, "couldn't fork child process");
                break;

            /* The child */
            case 0:
#endif
                jid = xp->pr_id;

                /* Always free jail info before going into jail */
                jails_done(&jls);

                if(jail_attach(jid) == -1)
                    err(1, "couldn't attach to jail");

                 r = kill_jail(argv[0]);
                 exit(r);
#ifdef _DEBUG
                 break;

            /* The parent */
            default:
                if(waitpid(child, &r, 0) == -1)
                     err(1, "error waiting for child process");

                if(WEXITSTATUS(r) != 0)
                    ret = WEXITSTATUS(r);
                break;
            };
#endif

            argc--;
            argv++;
        }

        jails_done(&jls);
        return ret;
    }
}

static void parse_jail_opts(int argc, char* argv[])
{
    char* t;
    int ch;
    int ishr = 0;

    g_verbose = 1;
    g_force = 1;
    g_usescripts = 1;

    t = strrchr(argv[0], '/');
    t = t ? t + 1 : argv[0];

    if(strcmp(t, "halt") == 0)
    {
        g_restart = 0;
        ishr = 1;
    }

    else if(strcmp(t, "reboot") == 0 ||
            strcmp(t, "restart") == 0)
    {
        g_restart = 1;
        ishr = 1;
    }

    /* Options for jkill */
    if(!ishr)
    {
        while((ch = getopt(argc, argv, "rt:")) != -1)
        {
            switch(ch)
            {
            case 'r':
                g_restart = 1;
                break;

            /* Timeout to use between kills */
            case 't':
                g_timeout = atoi(optarg);
                if(g_timeout <= 0)
                    errx(2, "invalid timeout argument: %s", optarg);
                break;

            case '?':
            default:
                usage_jail();
                break;
            }
        }
    }

    /* These are the options for 'halt' and 'reboot' */
    else
    {
        while((ch = getopt(argc, argv, "dk:lnqp")) != -1)
        {
            switch(ch)
            {
            case 'd':
            case 'k':
            case 'n':
            case 'q':
            case 'p':
                warnx("the '-%c' option is not supported from inside a jail", (char)ch);
                break;

            case 'l':
		break;

            case '?':
            default:
                usage_hr(t);
                break;
            }
        }
    }

    argc -= optind;
    argv += optind;

    if(argc > 0)
    {
        if(ishr)
            usage_hr(t);
        else
            usage_jail();
    }
}

static void parse_host_opts(int argc, char* argv[])
{
    int ch;

    while((ch = getopt(argc, argv, "fhkqrt:v")) != -1)
    {
        switch(ch)
        {
        case 'f':
            g_force = 1;
            break;

        case 'h':
            /* dummy for compatibility with killjail */
            warnx("the '-h' option has been depreciated");
            break;

        case 'k':
            g_usescripts = 0;
            break;

        case 'q':
            g_quiet = 1;
            g_verbose = 0;
            break;

        case 'r':
            g_restart = 1;
            break;

        /* Timeout to use between kills */
        case 't':
            g_timeout = atoi(optarg);
            if(g_timeout <= 0)
                errx(2, "invalid timeout argument: %s", optarg);
            break;

        case 'v':
            g_verbose = 1;
            g_quiet = 0;
            break;

        case '?':
        default:
            usage();
            break;
        }
    }

    if(!g_usescripts && g_restart)
        usage();

    argc -= optind;
    argv += optind;

    if(argc <= 0)
        usage();
}

#define SHUTDOWN_SCRIPT "/etc/rc.shutdown"
static char* SHUTDOWN_ARGS[] = { _PATH_BSHELL, SHUTDOWN_SCRIPT, NULL };

#define START_SCRIPT "/etc/rc"
static char* START_ARGS[] = { _PATH_BSHELL, START_SCRIPT, NULL };

static int kill_jail(const char* jail)
{
    kvm_t* kd = NULL;
    char errbuf[_POSIX2_LINE_MAX];
    int pass = 0;
    int timeout = 0;
    int ret = 0;
    int cmdargs = JAIL_RUN_CONSOLE;

    /* Open the kernel interface */
    kd = kvm_openfiles(_PATH_DEVNULL, _PATH_DEVNULL, NULL, O_RDONLY, errbuf);
    if(kd == NULL)
        errx(1, "couldn't connect to kernel: %s", errbuf);

    if(g_verbose)
        cmdargs |= JAIL_RUN_STDERR;

    /*
     * Multiple passes are used to do different things.
     * Each time the jails processes are listed.
     */
    while(1)
    {
        while(timeout > 0)
        {
            sleep(1);
            timeout--;

            if(!check_running_processes(kd))
                goto done;
        }

        switch(pass)
        {
        /* First pass is an orderly shutdown */
        case 0:

            /* Check if we have an executable shutdown script */
            if(g_usescripts && check_jail_command(jail, SHUTDOWN_SCRIPT))
                run_jail_command(jail, SHUTDOWN_ARGS[0], SHUTDOWN_ARGS, cmdargs);

            break;

        /* Okay now quit all processes in jail */
        case 1:
            kill_jail_processes(kd, SIGTERM);
            timeout = g_timeout;
            break;

        /* ... and again ... */
        case 2:
            kill_jail_processes(kd, SIGTERM);
            timeout = g_timeout;
            break;

        /* Okay now we force kill the processes if necessary */
        case 3:

            if(g_force)
            {
                /* If we get here, jailer looks like it's really irresponsive */
                if(!g_quiet)
                    warnx("%s: jail won't stop. forcing jail termination...", jail);

                kill_jail_processes(kd, SIGKILL);
                timeout = g_timeout;
            }

            break;

        case 4:

            /* And if that didn't do it, well then give up */
            if(!g_quiet)
                warnx("%s: couldn't stop jail, processes wouldn't die", jail);

            ret = 1;
            goto done;
        }

        pass++;

        if(!check_running_processes(kd))
            goto done;
    }

done:
    if(g_restart)
    {
        /* Check if we have an executable shutdown script */
        if(check_jail_command(jail, START_SCRIPT))
            run_jail_command(jail, START_ARGS[0], START_ARGS, cmdargs);
    }

    if(kd != NULL)
        kvm_close(kd);

    return ret;
}

static void kill_jail_processes(kvm_t* kd, int sig)
{
    struct kinfo_proc* kp;
    int nentries, i;
    pid_t cur;

    cur = getpid();

    /* Get a process listing */
    if((kp = kvm_getprocs(kd, KERN_PROC_ALL, 0, &nentries)) == 0)
        errx(1, "couldn't list processes: %s", kvm_geterr(kd));

    /* Okay now loop and look at each process' jail */
    for(i = 0; i < nentries; i++)
    {
        if(kp[i].ki_pid == cur)
            continue;

        if(kill(kp[i].ki_pid, sig) == -1)
        {
            if(errno != ESRCH)
                errx(1, "couldn't signal process: %d", (int)kp[i].ki_pid);
        }
    }
}

static int check_running_processes(kvm_t* kd)
{
    struct kinfo_proc* kp;
    int nentries, i;
    pid_t cur;

    cur = getpid();

    /* Get a process listing */
    if((kp = kvm_getprocs(kd, KERN_PROC_ALL, 0, &nentries)) == 0)
        errx(1, "couldn't list processes: %s", kvm_geterr(kd));

    if(nentries != 1)
        return 1;

    /* Okay now loop and look at each process' jail */
    for(i = 0; i < nentries; i++)
    {
        if(kp[i].ki_pid != cur)
            return 1;
    }

    return 0;
}

static void usage()
{
    fprintf(stderr, "usage: jkill [-fkqv] [-t timeout] jail ...\n");
    fprintf(stderr, "       jkill -r [-fqv] [-t timeout] jail ...\n");
    exit(2);
}

static void usage_jail()
{
    fprintf(stderr, "usage: jkill [-r] [-t timeout]\n");
    exit(2);
}

static void usage_hr(const char* name)
{
    fprintf(stderr, "usage: %s\n", name);
    exit(2);
}
