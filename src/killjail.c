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
#include <sys/stat.h>
#include <sys/param.h>
#include <sys/sysctl.h>
#include <sys/proc.h>
#include <sys/user.h>

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

#include "getjail.h"

#ifdef HAVE_CONFIG_H
#include "../config.h"
#endif

/* The big long stop process */
static int stopJail(char* jailName, int force);

/* Signals the jailer for various requests */
static int signalJail(char* jailName, int signal);

static void killProcesses(pid_t* pids, int signal);
static int getJailProcesses(const char* jailName, pid_t* pidJailer, pid_t** pids);

static void usage();


/* The timeout to wait between kills */
#define		DEFAULT_TIMEOUT		10
int g_timeout = DEFAULT_TIMEOUT;

/* To find the jailer process look for this command */
#define		JAILER_COMMAND		"jailer"

/* Supress warnings */
int g_quiet = 0;

int main(int argc, char* argv[])
{
	/* If this gets set then only signal jailer, no kill */
	int signal = 0;
	int ch = 0;
	int force = 0;
	int ret = 0;

	while((ch = getopt(argc, argv, "fhqrt:")) != -1)
	{
		switch(ch)
		{
		/* Force jail to shutdown */
		case 'f':
			force = 1;
			break;

		case 'q':
			g_quiet = 1;
			break;

		/* Send halt request to jailer */
		case 'h':
			signal = SIGQUIT;
			break;

		/* Send restart request to jailer */
		case 'r':
			signal = SIGHUP;
			break;

		/* Timeout to use between kills */
		case 't':
			g_timeout = atoi(optarg);
			if(g_timeout <= 0)
				errx(1, "invalid timeout argument: %s", optarg);
			break;

		case '?':
		default:
			usage();
		}
	}

	argc -= optind;
	argv += optind;

	/* Make sure we have a jailName */
	if(argc == 0)
		usage();

	/* For each jail */
	while(argc > 0)
	{
		/* If a signal option was set above then signal,
		   otherwise kill */
		if(signal == 0)
		{
			if(stopJail(*argv, force) != 0)
				ret = 1;
		}
		else
		{
			if(force)
				errx(1, "-f option incompatible with -r or -h");

			if(signalJail(*argv, signal) != 0)
				ret = 1;
		}

		argc--;
		argv++;
	}

	return ret;
}


int signalJail(char* jailName, int signal)
{
	pid_t jailerPid = 0;

	/* Only ask for jailer pid */
	getJailProcesses(jailName, &jailerPid, NULL);

	if(jailerPid == 0)
	{
		warnx("%s: jailer not running in jail", jailName);
		return 1;
	}

	if(kill(jailerPid, signal) < 0)
		err(1, "%s: couldn't signal jailer", jailName);

	return 0;
}


int stopJail(char* jailName, int force)
{
	pid_t jailerPid = 0;
	pid_t* jailProcesses = NULL;
	int pass = 0;
	int timeout = 0;
	int ret = 0;

	/*
	 * Multiple passes are used to do different things.
	 * Each time the jails processes are listed.
	 */
	while(ret == 0 &&
		getJailProcesses(jailName, &jailerPid, &jailProcesses))
	{

		if(timeout > 0)
		{
			sleep(1);
			timeout--;
		}

		else
		{

			switch(pass)
			{

			/* First pass is killing the jailer */
			case 0:

				if(jailerPid == 0)
				{
					/* No jailer */
					if(!g_quiet)
						warnx("%s: jailer not running in jail", jailName);
				}

				else
				{
					if(kill(jailerPid, SIGTERM) < 0 && errno != ESRCH)
						err(1, "%s: couldn't signal jailer:", jailName);

					else
						timeout = g_timeout;
				}

				break;


			/* Okay now quit all processes in jail */
			case 1:

				/* If we get here, jailer looks like it's irresponsive */
				if(jailerPid != 0 && !g_quiet)
					warnx("%s: jailer (pid %d) won't quit. terminating jail...", jailName, jailerPid);


				killProcesses(jailProcesses, SIGTERM);
				timeout = g_timeout;
				break;


			/* Okay now we force kill the processes if necessary */
			case 2:

				if(force)
				{
					/* If we get here, jailer looks like it's really irresponsive */
					if(!g_quiet)
						warnx("%s: jail won't stop. forcing jail termination...", jailName);

					killProcesses(jailProcesses, SIGKILL);
					timeout = g_timeout;
				}

				break;


			/* And if that didn't do it, well then give up */
			case 3:

				if(!g_quiet)
					warnx("%s: couldn't stop jail, processes wouldn't die", jailName);

				ret = 1;
				break;

			}

			pass++;
		}

		if(jailProcesses)
			free(jailProcesses);

	}

	if(pass == 0)
	{
		if(!g_quiet)
			warnx("%s: jail not running", jailName);

		ret = 1;
	}

	return ret;
}

void killProcesses(pid_t* pids, int signal)
{
	/* Note that we assume pids is null terminated
	   this is what getJailProcesses returns */

	while(*pids)
	{
		if(kill(*pids, signal) < 0)
		{
			/* We ignore missing process errors */
			if(errno != ESRCH)
				err(1, "couldn't kill process: %d", *pids);
		}

		pids++;
	}
}

int getJailProcesses(const char* jailName, pid_t* pidJailer, pid_t** pids)
{
	kvm_t *kd;
	struct kinfo_proc* kp;
	char errbuf[_POSIX2_LINE_MAX];
	char pidJail[JAIL_BUFF_SIZE];
	int nentries, i, j;

	/* Open the kernel interface */
	kd = kvm_openfiles(_PATH_DEVNULL, _PATH_DEVNULL, _PATH_DEVNULL,
					   O_RDONLY, errbuf);
	if(kd == 0)
		errx(1, "%s", errbuf);

	/* Get a process listing */
	if((kp = kvm_getprocs(kd, KERN_PROC_ALL, 0, &nentries)) == 0)
		errx(1, "%s", kvm_geterr(kd));

	/* Allocate memory */
	if(pids)
	{
		if((*pids = (pid_t*)malloc((nentries + 1) * sizeof(pid_t))) == NULL)
			err(1, "out of memory");
	}

	/* Okay now loop and look at each process' jail */
	for(i = 0, j = 0; i < nentries; i++)
	{
		pid_t pid;

#if __FreeBSD_version > 500000

		/* Check the flags first */
		if(!(kp[i].ki_flag & P_JAILED))
			continue;

		pid = kp[i].ki_pid;

#else

		/* Check the flags first */
		if(!(kp[i].kp_proc.p_flag & P_JAILED))
			continue;

		pid = kp[i].kp_proc.p_pid;

#endif

		/* Now actually get the jail name */
		if(getpidjail(pid, pidJail) < 0)
			continue;

		if(strcmp(pidJail, jailName))
			continue;

		/* Copy the PID over */
		if(pids)
			(*pids)[j++] = pid;

		/* If it's the jailer then copy that */
		if(pidJailer)
		{
#if __FreeBSD_version > 500000
			if(strstr(kp[i].ki_comm, JAILER_COMMAND))
#else
			if(strstr(kp[i].kp_proc.p_comm, JAILER_COMMAND))
#endif
				*pidJailer = pid;
		}

	}

	/* Null terminate pids array */
	if(pids)
		(*pids)[j] = 0;

	kvm_close(kd);

	return j == 0 ? 0 : 1;
}



static void usage()
{
	fprintf(stderr, "usage: killjail [ -h | -r ] [ -t timeout ] [ -qf ] jailname ...\n");
	exit(2);
}

