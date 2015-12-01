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

#include <stdlib.h>
#include <stdio.h>
#include <fcntl.h>
#include "getjail.h"

#define 	PROC_STATUS_PATH	"/proc/%d/status"

int getpidjail(pid_t pid, char* buff)
{
	int fd;
	size_t bytes;
	off_t off;

	/* Format the file name */
	if(snprintf(buff, JAIL_BUFF_SIZE, PROC_STATUS_PATH, pid))
	{
		/* Open the file */
		if((fd = open(buff, O_RDONLY)) >= 0)
		{
			/* Seek to the last bit */
			off = lseek(fd, SEEK_END, 0);

			if(off != -1)
			{
				off -= JAIL_BUFF_SIZE;
				if(off < 0) off = 0;
				lseek(fd, SEEK_SET, off);

				if((bytes = read(fd, buff, JAIL_BUFF_SIZE - 1)) > 0)
				{
					/* Okay now jailname should be the last token */
					while(isspace(buff[bytes - 1]))
						bytes--;

					buff[bytes] = 0;

					while(!isspace(buff[bytes - 1]))
						bytes--;

					memmove(buff, buff + bytes, JAIL_BUFF_SIZE - bytes);
					return 0;

				}
			}
		}
	}

	return -1;
}
