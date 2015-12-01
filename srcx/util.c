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
 *  James E. Quick <jq@quick.com>
 */

#include "config.h"

#include <sys/types.h>
#include <sys/param.h>
#include <sys/proc.h>
#include <sys/user.h>
#include <sys/stat.h>
#include <sys/jail.h>
#include <sys/sysctl.h>
#include <sys/file.h>
#include <sys/wait.h>

#include <err.h>
#include <errno.h>
#include <stdlib.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <kvm.h>
#include <paths.h>
#include <string.h>
#include <unistd.h>

#include <netinet/in.h>

#include "util.h"

extern char** environ;

void
jails_load (jails *jls)
{
	struct xprison *xp;

	memset (jls, 0, sizeof (jails));

	if(sysctlbyname("security.jail.list", NULL, &jls->length, NULL, 0) == -1)
		err(1, "couldn't list jails");

retry:

	if(jls->length <= 0)
	{
		jls->data = NULL;
		jls->last = NULL;
		return;
	}

	jls->data = calloc(jls->length, 1);
	if(jls->data == NULL)
		err(1, "out of memory");

	if(sysctlbyname("security.jail.list", jls->data, &jls->length, NULL, 0) == -1)
	{
		if(errno == ENOMEM)
		{
			free(jls->data);
			jls->data = NULL;
			goto retry;
		}

		err(1, "couldn't list jails");
	}

	xp = jls->data;
	if(jls->length < sizeof(*xp) || xp->pr_version != XPRISON_VERSION)
		errx(1, "kernel and userland out of sync");
}

struct xprison*
jails_next (jails *jls)
{
	struct xprison *xp = jls->last;
	unsigned char *data, *next, *end;

	if(xp == NULL)
	{
		xp = jls->data;
	}
	else
	{
		switch(xp->pr_version)
		{
		case 1:
		case 2:
			xp = xp + 1;
			break;
#ifdef JAIL_MULTIADDR
		case 3:
			data = (unsigned char*)(xp + 1);
			data += (xp->pr_ip4s * sizeof(struct in_addr));
			data += (xp->pr_ip6s * sizeof(struct in6_addr));
			xp = (struct xprison*)data;
			break;
#endif
		default:
			errx(1, "unknown version of jail structure: %d", xp->pr_version);
			break;
		}
	}

	if(xp == NULL)
		return NULL;

	next = (unsigned char*)(xp + 1);
	end = ((unsigned char*)jls->data) + jls->length;
	if (next > end)
		return NULL;

	if(xp->pr_version != XPRISON_VERSION)
		errx(1, "kernel and userland out of sync");

	jls->last = xp;
	return xp;
}

void
jails_done(jails *jls)
{
	memset(jls->data, 0, jls->length);
	free(jls->data);
	jls->data = NULL;
	jls->length = 0;
	jls->last = NULL;
}

struct xprison*
jails_find(jails *jls, const char* str)
{
	struct xprison *xp;
	char *e;
	int jid;

	jid = strtol(str, &e, 10);
	jls->last = NULL;

	for(;;)
	{
		xp = jails_next(jls);
		if(xp == NULL)
			return NULL;

		/* If it was all a number ... */
		if(!*e)
		{
			if(jid <= 0)
				errx(1, "invalid jail id: %s", str);
			if(jid == xp->pr_id)
				return xp;
		}

		/* A host name? */
		else
		{
			if(strcmp(xp->pr_host, str) == 0)
				return xp;
		}
	}

	/* Not reached */
}

int translate_jail_name(const char* str)
{
	struct xprison* xp;
	int jid = -1;
	jails jls;

	jails_load(&jls);
	xp = jails_find(&jls, str);
	if(xp != NULL)
		jid = xp->pr_id;
	jails_done(&jls);

	return jid;
}

int kvm_prepare_jail(struct xprison* xp)
{
    /*
     * Basically the kvm routines won't work in a jail unless there's
     * a /dev/null device for us to use as the file names. If it's
     * missing we have to create it.
     */

    struct stat sb;
    char* path;
    int nodir = 0;
    int nonull = 0;

    path = (char*)alloca(strlen(_PATH_DEVNULL) + 2 + strlen(xp->pr_path));

    strcpy(path, xp->pr_path);
    strcat(path, _PATH_DEVNULL);

    if(stat(path, &sb) == -1)
    {
        if(errno == ENOTDIR)
        {
            nodir = 1;
            nonull = 1;
        }

        else if(errno == ENOENT)
        {
            nonull = 1;
        }

        else
        {
            err(1, "couldn't stat file: %s", path);
        }
    }

    if(nodir)
    {
        strcpy(path, xp->pr_path);
        strcat(path, _PATH_DEV);

        if(mkdir(path, 0) == -1 ||
           chmod(path, S_IRWXU | S_IRGRP | S_IXGRP | S_IROTH | S_IXOTH) == -1)
        {
            warn("couldn't create %s directory", path);
            return -1;
        }
    }

    if(nonull)
    {
        mode_t mode = 0666 | S_IFCHR;
        dev_t dev = makedev(2, 2);

        strcpy(path, xp->pr_path);
        strcat(path, _PATH_DEVNULL);

        warnx("creating %s device in jail.", path);

        if(mknod(path, mode, dev) == -1)
        {
            warn("couldn't create %s device", path);
            return -1;
        }
    }

    return 0;
}

/*
 * in_jail
 * This code was written by James E. Quick mailto:jq@quick.com
 * The code may be freely re-used under the terms of the BSD copyright,
 * as long as this comment remains intact.
 */

int running_in_jail()
{
    int count;
    kvm_t* kd = 0;
    struct kinfo_proc* kp;
    int  result = -1;

    kd = kvm_open(_PATH_DEVNULL, _PATH_DEVNULL, NULL, O_RDONLY, NULL);
    if(kd == NULL)
        return -1;

    kp = kvm_getprocs(kd, KERN_PROC_PID, getpid(), &count);

    if(kp == NULL)
        result = -1;
    else
        result = (kp->ki_flag & P_JAILED) ? 1 : 0;

    kvm_close(kd);

    return result;
}


int check_jail_command(const char* jail, const char* cmd)
{
    struct stat sb;

    if(stat(cmd, &sb) == -1)
    {
        if(errno == EACCES || errno == ELOOP || errno == ENAMETOOLONG ||
           errno == ENOENT || errno == ENOTDIR)
        {
            warn("%s%scan't execute in jail: %s", jail ? jail : "",
                 jail ? ": " : "", cmd);
            return 0;
        }

        err(1, "%s%scouldn't stat file: %s", jail ? jail : "",
            jail ? ": " : "", cmd);
    }

    if(!(sb.st_mode & S_IFREG))
    {
        warnx("%s%snot a regular file: %s", jail ? jail : "",
                jail ? ": " : "", cmd);
        return 0;
    }

    if(sb.st_uid != 0)
    {
        warnx("%s%snot owned by root: %s", jail ? jail : "",
                jail ? ": " : "", cmd);
        return 0;
    }

    return 1;
}

int run_overlay_command(const char* jail, const char* cmd, char* env[],
                        char* args[])
{
    if(args)
        execve(cmd, args, env);
    else
        execle(cmd, cmd, NULL, env);

    warn("%s%serror executing: %s", jail ? jail : "",
          jail ? ": " : "", cmd);
    return 0;
}

int run_simple_command(const char* jail, const char* cmd, char* env[],
                       char* args[], int opts)
{
    pid_t pid;
    int status = 0;

    if(opts & JAIL_RUN_NOFORK)
        return run_overlay_command(jail, cmd, env, args);

    switch((pid = fork()))
    {
    case -1:
        err(1, "couldn't fork child process");
        break;

    /* This is the child here */
    case 0:
        unignore_signals ();
        if(args)
            execve(cmd, args, env);
        else
            execle(cmd, cmd, NULL, env);

        exit(errno);
        break;

    /* This is the parent process */
    default:

        /* If the processes exited then break out */
        if(waitpid(pid, &status, 0) == -1)
            err(1, "couldn't wait on child process");

        /* Return any status codes */
        if(WEXITSTATUS(status) != 0)
        {
            warnx("%s%serror executing: %s: %s", jail ? jail : "",
                  jail ? ": " : "", cmd, strerror(WEXITSTATUS(status)));
            return 0;
        }

        break;
    }

    return 1;
}

/* read & write ends of a pipe */
#define  READ_END   0
#define  WRITE_END  1

/* pre-set file descriptors */
#define  STDIN   0
#define  STDOUT  1
#define  STDERR  2

int run_dup_command(const char* jail, const char* cmd, char* env[],
                    char* args[], int opts)
{
    int outpipe[2];
    pid_t pid;

    /*
     * Special function to duplicate output of a command to two
     * files.
     *
     * NOTE: Yes, I know this may seem like overkill, but system,
     * popen and all those guys would hang with certain rc scripts.
     * Those which opened a daemon in the background ('&') but still
     * kept their output going to the same stdin/stdout handles.
     */

    /* Create a pipe for the child process */
    if(pipe(outpipe) < 0)
        return -1;

    switch(pid = fork())
    {
    case -1:
        err(1, "couldn't fork child process");
        break;

    /* This is the child here */
    case 0:
        {
            unignore_signals ();

            /* Fix up our end of the pipe */
            if(dup2(outpipe[WRITE_END], STDOUT) < 0 ||
               dup2(outpipe[WRITE_END], STDERR) < 0)
                exit(errno);

            /* Okay, now run whatever command it was */
            if(args)
                execve(cmd, args, env ? env : environ);
            else
                execle(cmd, cmd, NULL, env ? env : environ);

            /* In case it returns then have to do this to get
               children to disconnect from stdout */
            fflush(stdout);
            fclose(stdout);
            close(outpipe[WRITE_END]);

            exit(errno);
        }
        break;


    /* And this is the parent */
    default:
        {
            int console = -1;
            int ret;
            int status = 0;
            int waited = 0;
            fd_set readmask;
            char buff[256];
            struct timeval timeout = { 0, 10000 };

            FD_ZERO(&readmask);

            /* Open the console file and write the header */
            if(opts & JAIL_RUN_CONSOLE)
                console = open(_PATH_CONSOLE, O_WRONLY | O_APPEND);

            /* No blocking on the child processes pipe */
            fcntl(outpipe[READ_END], F_SETFL, fcntl(outpipe[READ_END], F_GETFL, 0) | O_NONBLOCK);

            /* Loop until the process dies or no more output */
            while(1)
            {
                FD_SET(outpipe[READ_END], &readmask);

                if(select(FD_SETSIZE, &readmask, NULL, NULL, &timeout) == -1)
                    err(1, "couldn't select");

                if(FD_ISSET(outpipe[READ_END], &readmask))
                {
                    /* Read text */
                    while((ret = read(outpipe[READ_END], buff, 256)) > 0)
                    {
                        if(opts & JAIL_RUN_STDOUT)
                            write(STDOUT, buff, ret);

                        if(opts & JAIL_RUN_STDERR)
                            write(STDERR, buff, ret);

                        if(console != -1)
                            write(console, buff, ret);
                    }
                }

                /* Or if there's an error or end of file */
                if((ret == -1 && errno != EAGAIN) || ret == 0)
                    break;

                /* If the processes exited then break out */
                if(waitpid(pid, &status, WNOHANG) == pid)
                {
                    waited = 1;
                    break;
                }
            }

            if(!waited)
                waitpid(pid, &status, 0);

            /* Return any status codes */
            if(WEXITSTATUS(status) != 0)
            {
                warnx("%s%serror executing: %s: %s", jail ? jail : "",
                    jail ? ": " : "", cmd, strerror(WEXITSTATUS(status)));
                return 0;
            }

            /* Clean up */
            close(outpipe[READ_END]);

            if(console != -1)
                close(console);
        }
        break;
    }

    return 1;
}


int run_jail_command(const char* jail, const char* cmd, char* args[], int opts)
{
    char* env[5];
    char* t;
    int j;

    memset(env, 0, sizeof(env));

#define MAKE_ENV_VAR(n)                             \
    t = getenv(n);                                  \
    if(t != NULL)                                   \
    {                                               \
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

    if(opts & JAIL_RUN_OUTPUT)
        return run_dup_command(jail, cmd, env, args, opts);
    else
        return run_simple_command(jail, cmd, env, args, opts);
}

void ignore_signals(void)
{
    signal(SIGHUP, SIG_IGN);
    signal(SIGPIPE, SIG_IGN);
    signal(SIGTERM, SIG_IGN);
}

void unignore_signals(void)
{
    signal(SIGHUP, SIG_DFL);
    signal(SIGPIPE, SIG_DFL);
    signal(SIGTERM, SIG_DFL);
}

