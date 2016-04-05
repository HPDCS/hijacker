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
* @file list.c
* @brief Doubly-linked list functions
* @author Simone Economo
*/

#include <stdio.h>
#include <stdlib.h>

#include <utils.h>
#include <prints.h>
#include <structs/structs.h>


__blind__ list_node_t *list_insert(list_t *list, void *elem, list_node_t *pivot,
                                   list_insert_mode mode) {
  list_node_t *node;

  if (!list) {
    hinternal();
  }

  node = hcalloc(sizeof(list_node_t));
  node->elem = elem;

  if (list_is_empty(list)) {
    list->first = list->last = node;
  }

  else if (!pivot) {
    // If a pivot can be selected, it *must* be selected
    hinternal();
  }

  else if (mode == INSERT_AFTER) {
    if (pivot->next) {
      pivot->next->prev = node;
    } else {
      list->last = node;
    }

    node->prev = pivot;
    node->next = pivot->next;
    pivot->next = node;
  }

  else if (mode == INSERT_BEFORE) {
    if (pivot->prev) {
      pivot->prev->next = node;
    } else {
      list->first = node;
    }

    node->next = pivot;
    node->prev = pivot->prev;
    pivot->prev = node;
  }

  list->size += 1;

  return node;
}


__blind__ list_range_t *list_insert_many(list_t *list, list_t *nodes,
                                         list_node_t *pivot, list_insert_mode mode) {
  list_node_t *node, *first, *last;

  if (!list || !nodes) {
    hinternal();
  }

  list_for_each(nodes, node) {
    list_insert(list, node->elem, pivot, mode);
  }

  return range(nodes->first, nodes->last);
}


__blind__ void *list_remove(list_t *list, list_node_t *node) {
  void *elem;

  if (!list || !node || list_is_empty(list)) {
    hinternal();
  }

  elem = node->elem;

  if (node->prev) {
    node->prev->next = node->next;
  } else {
    list->first = node->next;
  }

  if (node->next) {
    node->next->prev = node->prev;
  } else {
    list->last = node->prev;
  }

  list->size -= 1;
  free(node);

  return elem;
}


__blind__ void *list_remove_many(list_t *list, list_t *nodes) {
  // Two static pointers are maintained across function calls:
  // one is an iterator to the currently-visited list node,
  // the other one stores in advance the next node to visit
  // in order to prevent accessing freed memory.
  static list_node_t *current;
  static list_node_t *next;

  void *elem;

  if (!list || !range_valid(nodes)) {
    hinternal();
  }

  // Last iteration: set iterator to NULL and invalidate the slice
  if (current == (list_node_t *) &current) {
    return current = NULL;
  }

  // First iteration: set iterator to the beginning of the range
  else if (!current) {
    current = nodes.first;
    next = current->next;
  }

  // Remove the current list node and return the payload
  elem = list_remove(list, current);

  if (next != nodes.last->next) {
    // Prepare next iteration: advance iterator to the next
    // element of the list
    current = next;
    next = next->next;
  } else {
    // The next iteration is the last: we use a special value
    // to indicate this fact
    current = (list_node_t *) &current;
  }

  // Return the payload to the caller for further consumption
  return elem;
}


list_node_t *list_find(list_t *list, void *elem) {
  list_node_t *node;

  if (!list) {
    hinternal();
  }

  list_for_each(list, node) {
    if (node->elem == elem) {
      return node;
    }
  }

  return NULL;
}
