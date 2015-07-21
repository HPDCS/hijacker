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
* @brief Utility functions and data structures
* @author Davide Cingolani
* @author Simone Economo
* @date April 17, 2014
*/

#include <stdio.h>
#include <stdlib.h>

#include <utils.h>

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

	printf ("       Address                     Hexadecimal values                      Printable     \n" );
	printf ("   ----------------  ------------------------------------------------  ------------------\n" );

	// Process every byte in the data.
	if (len % 16 != 0)
		count = (((int) (len / 16) + 1) * 16);
	else
		count = len;

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
				printf ("   (%5d) %08x ", i, i);
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

			// Add a three-char long space for the missing character in the second column.
			printf("   ");

			// Add a printable dot for the missing character in the third column.
			buff[i % 16] = '.';
			buff[(i % 16) + 1] = '\0';
		}
	}

	// And print the final ASCII bit.
	printf ("  |%s|\n", buff);
}

void ll_move(linked_list *from, linked_list *to) {
	to->first = from->first;
	from->first = NULL;
	to->last = from->last;
	from->last = NULL;
}

inline bool ll_empty(linked_list *list) {
	return (list->first ? false : true);
}

void ll_push(linked_list *list, void *elem) {
	ll_node *node;

	node = calloc(sizeof(ll_node), 1);
  node->elem = elem;

  if (ll_empty(list)) {
    list->first = list->last = node;
  }
  else if (list->first == list->last) {
  	list->last = list->first->next = node;
  	node->prev = list->first;
  }
  else {
  	list->last->next = node;
  	node->prev = list->last;
  	list->last = node;
  }
}

void ll_push_first(linked_list *list, void *elem) {
	ll_node *node;

	node = calloc(sizeof(ll_node), 1);
  node->elem = elem;

  if (ll_empty(list)) {
    list->first = list->last = node;
  }
  else if (list->first == list->last) {
  	list->first = list->last->prev = node;
  	node->next = list->last;
  }
  else {
  	list->first->prev = node;
  	node->next = list->first;
  	list->first = node;
  }
}

void *ll_pop(linked_list *list) {
	ll_node *node;
	void *elem;

  if (!ll_empty(list)) {
		if (list->first == list->last) {
			node = list->last;
			list->first = list->last = NULL;
		}
		else if (list->first->next == list->last) {
			node = list->last;
			list->first->next = NULL;
			list->last = list->first;
		}
		else {
			node = list->last;
			list->last->prev->next = NULL;
			list->last = list->last->prev;
		}
	}

	if (node) {
		elem = node->elem;
		free(node);
	}

	return elem;
}

void *ll_pop_first(linked_list *list) {
	ll_node *node;
	void *elem;

  if (!ll_empty(list)) {
		if (list->first == list->last) {
			node = list->first;
			list->first = list->last = NULL;
		}
		else if (list->first->next == list->last) {
			node = list->first;
			list->last->prev = NULL;
			list->first = list->last;
		}
		else {
			node = list->first;
			list->first->next->prev = NULL;
			list->first = list->first->next;
		}
	}

	if (node) {
		elem = node->elem;
		free(node);
	}

	return elem;
}
