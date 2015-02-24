/**
*                       Copyright (C) 2008-2015 HPDCS Group
*                       http://www.dis.uniroma1.it/~hpdcs
*
*
* This file is part of the Hijacker static binary instrumentation tool.
*
* Hijacker is free software; you can redistribute it and/or modify it under the
* terms of the GNU General Public License as published by the Free Software
* Foundation; either version 3 of the License, or (at your option) any later
* version.
*
* Hijacker is distributed in the hope that it will be useful, but WITHOUT ANY
* WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR
* A PARTICULAR PURPOSE. See the GNU General Public License for more details.
*
* You should have received a copy of the GNU General Public License along with
* hijacker; if not, write to the Free Software Foundation, Inc.,
* 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
*
* @file utils.c
* @brief Utility functions
* @author Davide Cingolani
* @date April 17, 2014
*/

#include <stdio.h>
#include "utils.h"

/**
 * Perform a hexdump of data.
 * Stores into a preallocated buffer, pointed to by the 'dump' argument,
 * the hexadecimal dump of the 'len' bytes found starting from 'addr' pointer.
 *
 * @param addr Pointer to the data buffer to dump
 *
 * @param len Number of byte to read
 */
void hexdump (void *addr, int len) {
	int i;
	int count;
	unsigned char buff[17];
	unsigned char *pc = (unsigned char*)addr;

	if(len <= 0) {
		return;
	}

	printf ("       Address                     Hexadecimal values                      Printable\n" );
	printf ("   ----------------  ------------------------------------------------  ------------------\n" );

	// Process every byte in the data.
	count = (((int) (len / 16) + 1) * 16);
	for (i = 0; i < count; i++) {

		// Multiple of 8 means mid-line (add a mid-space)
		if((i % 8) == 0) {
			if (i != 0)
				printf(" ");
		}

		if (i < len) {
			// Multiple of 16 means new line (with line offset).
			if ((i % 16) == 0) {
				// Just don't print ASCII for the zeroth line.
				if (i != 0)
					printf (" |%s|\n", buff);

				// Output the offset.
				printf ("   (%5d) %08lx ", i, i);
			}

			// Now the hex code for the specific character.
			printf (" %02x", pc[i]);

			// And store a printable ASCII character for later.
			if ((pc[i] < 0x20) || (pc[i] > 0x7e))
				buff[i % 16] = '.';
			else
				buff[i % 16] = pc[i];
			buff[(i % 16) + 1] = '\0';
		}

		// Pad out last line if not exactly 16 characters.
		else {
			printf("   ");
			buff[i % 16] = '.';
			buff[(i % 16) + 1] = '\0';
		}
	}

	// And print the final ASCII bit.
	printf ("  |%s|\n", buff);
}
