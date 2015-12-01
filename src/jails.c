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
#include <stdio.h>
#include <err.h>
#include <errno.h>
#include <kvm.h>
#include <limits.h>
#include <fcntl.h>

#include "getjail.h"

#ifdef HAVE_CONFIG_H
#include "../config.h"
#endif

static int listJails();
static void usage();

int main(int argc, char* argv[])
{
	/* Nice main :) */
	return listJails() >= 0 ? 0 : 1;
}


int listJails()
{
	kvm_t *kd;
	struct kinfo_proc* kp;
	char errbuf[_POSIX2_LINE_MAX];
	char jailName[JAIL_BUFF_SIZE];
	int nentries, i;


	char* jails = NULL;		/* jail list buffer */
	size_t nextJail = 0;	/* current write positon */
	size_t endJails = 0;	/* size of buffer */
	int numJails = 0;		/* return value */


	/* Open kernel interface */
	kd = kvm_openfiles(_PATH_DEVNULL, _PATH_DEVNULL, _PATH_DEVNULL,
					   O_RDONLY, errbuf);
	if(kd == 0)
		errx(1, "%s", errbuf);

	/* Get a process listing */
	if((kp = kvm_getprocs(kd, KERN_PROC_ALL, 0, &nentries)) == 0)
		errx(1, "%s", kvm_geterr(kd));


	/* Okay now loop through and look for the jails */
	for(i = 0; i < nentries; i++)
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

		/* Get this processes jail name */
		if(getpidjail(pid, jailName) < 0)
			continue;

		if(jails)
		{
			char* j;

			/* See if that jail name was already taken */
			for(j = jails; *j != NULL; j += strlen(j) + 1)
			{
				if(!strcmp(jailName, j))
					break;
			}

			/* Can't do this in loop above */
			if(*j)
				continue;
		}


		/* Okay we got a jail name */


		/* Allocate if necessary enough space for it */
		if(nextJail + strlen(jailName) + 2 > endJails)
		{
			endJails += (JAIL_BUFF_SIZE * 0x2);
			jails = (char*)realloc(jails, endJails);
			if(!jails)
				errx(1, "out of memory");
		}


		/* Put the jail name in the buffer */
		strcpy(jails + nextJail, jailName);
		nextJail += strlen(jailName) + 1;
		jails[nextJail] = 0;
		numJails++;

		/* And print it */
		fprintf(stdout, "%s\n", jailName);
	}

	kvm_close(kd);

	return numJails;
}

static void usage()
{
	fprintf(stderr, "usage: jails\n");
	exit(2);
}

