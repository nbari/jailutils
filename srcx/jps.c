/*
 * Copyright (c) 2004, Stefan Walter
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
#include <sys/param.h>
#include <sys/sysctl.h>
#include <sys/user.h>
#include <sys/jail.h>

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <kvm.h>
#include <paths.h>
#include <limits.h>
#include <err.h>

#include "util.h"

#ifdef HAVE_CONFIG_H
#include "../config.h"
#endif

static void usage();
static void print_jail_ids();
static void run_jail_ps(int argc, char* argv[]);

int main(int argc, char* argv[])
{
    struct xprison* xp = NULL;
    jails jls;
    size_t len;
    int jid, ch = 0;
    int simple = 0;

    while((ch = getopt(argc, argv, "i")) != -1)
    {
        switch(ch)
        {
        case 'i':
            simple = 1;
            break;

        case '?':
        default:
            usage();
        }
    }

    argc -= optind;
    argv += optind;

    /* Make sure we have a jail name or id */
    if(argc == 0)
        usage();

    if(running_in_jail() != 0)
        errx(1, "can't run from inside jail");

    /* Translate the jail name into an id if neccessary */
    jails_load(&jls);
    xp = jails_find(&jls, argv[0]);

    if(xp == NULL)
        errx(1, "unknown jail host name: %s", argv[0]);

    argc--;
    argv++;

    /* This makes sure we can use kvm funcs in jail */
    kvm_prepare_jail(xp);

    jid = xp->pr_id;

    /* Always free jail info before going into jail */
    jails_done(&jls);

    /* Go into the jail */
    if(jail_attach(jid) == -1)
        err(1, "couldn't attach to jail");

    if(simple)
    {
        if(argc > 0)
            usage();

        print_jail_ids();
    }

    else
    {
        /* This function never returns */
        run_jail_ps(argc, argv);
    }

    return 0;
}

static void usage()
{
    fprintf(stderr, "usage: jps [-i] jail [ ps_options ... ]\n");
    exit(2);
}

static void run_jail_ps(int argc, char* argv[])
{
    char** args;
    int i;

    if(!check_jail_command(NULL, "/bin/ps"))
        exit(1);

    /*
     * TODO: We need to purge down the environment here.
     * If the jail is in any way malicious or compromised
     * then it could have replaced /bin/ps which we run...
     */

    args = (char**)alloca(sizeof(char*) * (argc + 2));
    args[0] = "ps";

    for(i = 0; i < argc; i++)
        args[i + 1] = argv[i];

    args[i + 1] = NULL;

    run_jail_command(NULL, "/bin/ps", args, JAIL_RUN_NOFORK);
}

static void print_jail_ids()
{
    kvm_t* kd;
    int nentries, i;
    struct kinfo_proc* kp;
    char errbuf[_POSIX2_LINE_MAX];

    /* Open kernel interface */
    kd = kvm_openfiles(_PATH_DEVNULL, _PATH_DEVNULL, NULL, O_RDONLY, errbuf);
    if(kd == NULL)
        errx(1, "couldn't connect to kernel: %s", errbuf);

    /* Get all processes and print the pids */
    if((kp = kvm_getprocs(kd, KERN_PROC_ALL, 0, &nentries)) == 0)
        errx(1, "couldn't list processes: %s", kvm_geterr(kd));

    for(i = 0; i < nentries; i++)
    {
        if(kp[i].ki_pid != getpid())
            printf("%d ", (int)(kp[i].ki_pid));
    }

    fputc('\n', stdout);
    kvm_close(kd);
}
