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
* @file utils.h
* @brief Utility functions and data structures
* @author Davide Cingolani
* @author Simone Economo
* @date April 17, 2014
*/

#ifndef _UTILS_H_
#define _UTILS_H_

#include <stdbool.h>


// Checks whether two strings have the same sequence of characters
#define str_equal(str_a, str_b) ( \
  strcmp((const char *) (str_a), (const char *) (str_b)) == 0 \
)

// Checks whether 'str' has prefix 'pre'
#define str_prefix(str, pre) ( \
  strncmp((const char *) (pre), (const char *) (str), \
    strlen((const char *) (pre))) == 0 \
)

/**
 * Perform a hexdump of data.
 * Stores into a preallocated buffer, pointed to by the 'dump' argument,
 * the hexadecimal dump of the 'len' bytes found starting from 'addr' pointer.
 *
 * @param addr Pointer to the data buffer to dump
 *
 * @param len Number of byte to read
 */
void hexdump (void *addr, int len);


// Linked list
// -----------

typedef struct ll_node {
	struct ll_node *next;
	struct ll_node *prev;
	void *elem;
} ll_node;

typedef struct {
	ll_node *first;
	ll_node *last;
} linked_list;

// Graph
// -----

typedef enum {
	VISIT_FORWARD,
	VISIT_BACKWARD
} graph_visit_dir;

typedef enum {
	VISIT_DEPTH,
	VISIT_BREADTH
} graph_visit_policy;

typedef bool (*graph_visit_func)(void *elem, void *data);

typedef struct {
  void *payload;
  linked_list scheduled;
  linked_list visited;
  graph_visit_policy policy;
  graph_visit_dir dir;
  graph_visit_func pre_func;
  graph_visit_func post_func;
} graph_visit;

extern void ll_init(linked_list *list);

extern void ll_move(linked_list *from, linked_list *to);
extern bool ll_empty(linked_list *list);

extern void ll_push(linked_list *list, void *elem);
extern void ll_push_first(linked_list *list, void *elem);

extern void *ll_pop(linked_list *list);
extern void *ll_pop_first(linked_list *list);

#endif /* _UTILS_H_ */
