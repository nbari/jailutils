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
#include <sys/stat.h>

#include <netinet/in.h>
#include <arpa/inet.h>

#include <paths.h>
#include <stdio.h>
#include <err.h>
#include <errno.h>
#include <unistd.h>
#include <limits.h>
#include <stdlib.h>

#ifdef HAVE_CONFIG_H
#include "../config.h"
#endif

#define START_SCRIPT "/etc/rc"
static char* START_ARGS[] = { _PATH_BSHELL, START_SCRIPT };

static void usage();
static void check_command(const char* cmd);
static void run_command(const char* cmd, char* args[]);

int main(int argc, char* argv[])
{
  int ch;
  struct jail j;
  struct in_addr in;

  argc--;
  argv++;

  if(argc < 3)
    usage();

  if(getuid() != 0)
    errx(1, "must be run as root");

  if(chdir(argv[0]) != 0)
    err(1, "couldn't change to jail directory: %s", argv[0]);

  if(inet_aton(argv[2], &in) != 1)
    errx(1, "invalid ip address: %s", argv[2]);

  memset(&j, 0, sizeof(j));
  j.version = 0;
  j.path = argv[0];
  j.hostname = argv[1];
  j.ip_number = ntohl(in.s_addr);

  /* Here's where we actually go into the jail */
  if(jail(&j) != 0)
    err(1, "couldn't create jail");

  argc -= 3;
  argv += 3;

  if(argc == 0)
  {
    check_command(START_SCRIPT);
    run_command(START_ARGS[0], START_ARGS);
  }

  else
  {
    check_command(argv[0]);
    run_command(argv[0], argv);
  }

  return 0;
}

static void usage()
{
  fprintf(stderr, "usage: jstart path hostname ip-number [command ...]\n");
  exit(2);
}

static void check_command(const char* cmd)
{
  struct stat sb;

  if(stat(cmd, &sb) == -1)
  {
    if(errno == EACCES || errno == ELOOP || errno == ENAMETOOLONG ||
       errno == ENOENT || errno == ENOTDIR)
    {
      err(1, "can't execute in jail: %s", cmd);
    }

    err(1, "couldn't stat file: %s", cmd);
  }

  if(!(sb.st_mode & S_IFREG))
    errx(1, "not a regular file: %s", cmd);

  if(sb.st_uid != 0)
    errx(1, "not owned by root: %s", cmd);
}

static void run_command(const char* cmd, char* args[])
{
  char* env[5];
  char* t;
  int j;

  memset(env, 0, sizeof(env));

#define MAKE_ENV_VAR(n)                         \
  t = getenv(n);                                \
  if(t != NULL)                                 \
  {                                             \
    env[j] = alloca(strlen(n) + 2 + strlen(t)); \
    sprintf(env[j], "%s=%s", (char*)(n), t);    \
    j++;                                        \
  }

  /* Prepare an environment for the cmd */
  env[0] = "PATH=" _PATH_STDPATH;
  j = 1;

  MAKE_ENV_VAR("TERM");
  MAKE_ENV_VAR("COLUMNS");
  MAKE_ENV_VAR("LINES");

  if(execve(cmd, args, env) != 0)
    err(1, "couldn't execute command: %s", cmd);
}

