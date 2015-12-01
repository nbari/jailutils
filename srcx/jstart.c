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

/*
 * Original code and ideas from FreeBSD's jail.c written by
 *  <phk@FreeBSD.ORG>
 */

#include <sys/types.h>
#include <sys/param.h>
#include <sys/jail.h>
#include <sys/socket.h>

#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>

#include <paths.h>
#include <stdio.h>
#include <stdlib.h>
#include <err.h>
#include <unistd.h>
#include <limits.h>
#include <string.h>

#include "util.h"

#ifdef HAVE_CONFIG_H
#include "../config.h"
#endif

#define START_SCRIPT "/etc/rc"
static char* START_ARGS[] = { _PATH_BSHELL, START_SCRIPT, NULL };

static void usage();

/* Jail structure with multi address patch */
#if defined(JAIL_MULTIPATCH)

static void allocate_address(char* arg, struct jail* j)
{
    struct in_addr in;
    char *ip;
    int i = 0;

    /* Count number of ips */
    for(i = 1, ip = arg; *ip; ip++)
    {
        if(*ip == ',')
            i++;
    }

    /* Allocate memory */
    if((j->ips = (u_int32_t*)malloc(sizeof(u_int32_t) * i)) == NULL)
        errx(1, "out of memory");

    for(i = 0, ip = strtok(arg, ","); ip; i++, ip = strtok(NULL, ","))
    {
        if(inet_aton(ip, &in) == 0)
            errx(1, "invalid ip address: %s", ip);
        j->ips[i] = ntohl(in.s_addr);
    }

    j->nips = i;
    j->version = 1;
}

static void free_address(struct jail* j)
{
    free(j->ips);
}

/* Jail structure with multi address (FreeBSD 7.2+) */
#elif defined(JAIL_MULTIADDR)

static void add_addresses(struct jail *j, struct addrinfo *all)
{
    struct addrinfo *res;
    void *mem;

    for(res = all; res; res = res->ai_next)
    {
        switch(res->ai_family)
        {
        case AF_INET:
            j->ip4 = realloc(j->ip4, sizeof (*(j->ip4)) * (j->ip4s + 1));
            if(j->ip4 == NULL)
                errx(1, "out of memory");
            memcpy(j->ip4 + j->ip4s, &((struct sockaddr_in*)res->ai_addr)->sin_addr, sizeof (*(j->ip4)));
            ++j->ip4s;
            break;
#ifdef HAVE_INET6
        case AF_INET6:
            j->ip6 = realloc(j->ip6, sizeof (*(j->ip6)) * (j->ip6s + 1));
            if(j->ip6 == NULL)
                errx(1, "out of memory");
            memcpy(j->ip6 + j->ip6s, &((struct sockaddr_in6*)res->ai_addr)->sin6_addr, sizeof (*(j->ip6)));
            ++j->ip6s;
            break;
#endif /* HAVE_INET6 */
        default:
            errx(1, "Address family %d not supported", res->ai_family);
        }
    }
}

static void allocate_address(char* arg, struct jail* j)
{
    struct addrinfo hints, *res;
    struct in_addr in;
    char *ip;
    int error, i = 0;

    j->version = JAIL_API_VERSION;
    j->ip4s = j->ip6s = 0;
    j->ip4 = NULL;
    j->ip6 = NULL;

    memset(&hints, 0, sizeof(hints));
    hints.ai_protocol = IPPROTO_TCP;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_family = PF_UNSPEC;
    hints.ai_flags = AI_NUMERICHOST;

    for(i = 0, ip = strtok(arg, ","); ip; i++, ip = strtok(NULL, ","))
    {
        error = getaddrinfo(ip, NULL, &hints, &res);
        if(error != 0)
            errx(1, "invalid ip address: %s", ip);
        add_addresses(j, res);
        freeaddrinfo(res);
    }
}

static void free_address(struct jail* j)
{
    free(j->ip4);
    free(j->ip6);
}

/* No jail multi addrs */
#else

static void allocate_address(char* arg, struct jail* j)
{
    struct in_addr in;

    if(inet_aton(arg, &in) != 1)
        errx(1, "invalid ip address: %s", arg);
    j->ip_number = ntohl(in.s_addr);
    j->version = 0;
}

static void free_address(struct jail* j)
{
    /* Nothing to do */
}

#endif /* !JAIL_MULTIPATCH */


int main(int argc, char* argv[])
{
    int ch, jid;
    struct jail j;
    int printjid = 0;

    while((ch = getopt(argc, argv, "i")) != -1)
    {
        switch(ch)
        {
        case 'i':
            printjid = 1;
            break;

        case '?':
        default:
            usage();
        }
    }

    argc -= optind;
    argv += optind;

    if(argc < 3)
        usage();

    if(getuid() != 0)
        errx(1, "must be run as root");

    if(chdir(argv[0]) != 0)
        err(1, "couldn't change to jail directory: %s", argv[0]);

    memset(&j, 0, sizeof(j));
    j.path = argv[0];
    j.hostname = argv[1];

    allocate_address(argv[2], &j);

    /* Here's where we actually go into the jail */
    jid = jail(&j);
    if(jid == -1)
        err(1, "couldn't create jail");

    free_address(&j);

    if(printjid)
    {
        printf("%d\n", jid);
        fflush(stdout);
    }

    argc -= 3;
    argv += 3;

    if(argc == 0)
    {
        if(!check_jail_command(NULL, START_SCRIPT))
            exit(1);

        run_jail_command(NULL, START_ARGS[0], START_ARGS,
                         JAIL_RUN_CONSOLE | JAIL_RUN_STDOUT);
    }

    else
    {
        if(!check_jail_command(NULL, argv[0]))
            exit(1);

        run_jail_command(NULL, argv[0], argv,
                         JAIL_RUN_CONSOLE | JAIL_RUN_STDOUT);
    }

    return 0;
}

static void usage()
{
#ifdef JAIL_MULTIPATCH
    fprintf(stderr, "usage: jstart [-i] path hostname ip[,ip...] [command ...]\n");
#else
    fprintf(stderr, "usage: jstart [-i] path hostname ip-number [command ...]\n");
#endif
    exit(2);
}


