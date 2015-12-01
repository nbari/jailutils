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

#ifndef __UTIL_H__
#define __UTIL_H__

struct xprison;

int translate_jail_name(const char* str);
int running_in_jail();

typedef struct jails {
	void *data;
	size_t length;
	struct xprison *last;
} jails;

void jails_load(jails *jls);
struct xprison* jails_next(jails *jls);
struct xprison* jails_find(jails *jls, const char *str);
void jails_done(jails *jls);

#define JAIL_RUN_CONSOLE	0x00000001	/* Output stuff to the jail console if available */
#define JAIL_RUN_STDOUT		0x00000002	/* Output to stdout */
#define JAIL_RUN_STDERR		0x00000004	/* Output to stderr */
#define JAIL_RUN_OUTPUT		0x0000000F	/* All the output types */

#define JAIL_RUN_NOFORK		0x00000010	/* Don't fork, overlay current process */

int run_jail_command(const char* jail, const char* cmd, char* args[], int opts);
int check_jail_command(const char* jail, const char* cmd);

void ignore_signals(void);
void unignore_signals(void);

int kvm_prepare_jail(struct xprison* xp);

#endif /* __UTIL_H__ */

