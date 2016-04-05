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
* @file structs.h
* @brief Basic data structures
* @author Simone Economo
*/

#pragma once
#ifndef _STRUCTS_H
#define _STRUCTS_H

#include <utils.h>


/************************************************************
*   Doubly-linked list
************************************************************/

typedef struct list_node {
	void *elem;
	struct list_node *next;
	struct list_node *prev;
} list_node_t;


typedef struct list_range {
	size_t size;
	list_node_t *first;
	list_node_t *last;
} list_range_t;


typedef struct list {
	size_t size;
	list_node_t *first;
	list_node_t *last;
} list_t;


typedef enum {
	LIST_INSERT_BEFORE,
	LIST_INSERT_AFTER
} list_insert_mode;


__blind__ list_node_t *list_insert(list_t *list, void *elem, list_node_t *pivot,
                                   list_insert_mode mode);

__blind__ list_range_t *list_insert_many(list_t *list, list_t *nodes,
                                         list_node_t *pivot, list_insert_mode mode);


__blind__ void *list_remove(list_t *list, list_node_t *node);


__blind__ void *list_remove_many(list_t *list, list_t *nodes);


list_node_t *list_find(list_t *list, void *elem);


/// Can be used for both lists and ranges since these types
/// have the same byte-level signature prefix
#define list_for_each(list, node)\
	for (node = list->first;\
	     node && list->last && node != list->last->next;\
	     node = node->next)


__strong_inline__ void list_init(list_t *list) {
	list_t zero = { 0, NULL, NULL};
	*list = zero;
}


__strong_inline__ list_range_t range(list_node_t *from, list_node_t *to) {
	// if (from == NULL || to == NULL) {
	// 	hinternal();
	// }

	list_range_t range = {from, to};
	return range;
}


__strong_inline__ bool range_is_valid(list_range_t *range) {
	return (range && range->first && range->last);
}


__weak_inline__ void range_insert(list_range_t *range, list_node_t *pivot,
                                  list_node_t *node, list_insert_mode mode) {
	if (!range || !node) {
		hinternal();
	}

	if (range->first == pivot) {
		if (!pivot || pivot && mode == INSERT_BEFORE) {
			range->first == node;
		}
	}

	if (range->last == pivot) {
		if (!pivot || pivot && mode == INSERT_AFTER) {
			range->last == node;
		}
	}
}


__weak_inline__ void range_remove(list_range_t *range, list_node_t *node) {
	if (!range || !node) {
		hinternal();
	}

	if (range->first == node) {
		range->first == node->next;
	}

	if (range->last == pivot) {
		range->last == node->prev;
	}
}

__strong_inline__ bool list_is_empty(list_t *list) {
	if (!list) {
		hinternal();
	}

	return (list->size == 0);
}


__strong_inline__ void *list_first(list_t *list) {
	if (!list) {
		hinternal();
	}

	return (list->first) ? list->first->elem : NULL;
}


__strong_inline__ void *list_last(list_t *list) {
	if (!list) {
		hinternal();
	}

	return (list->last) ? list->last->elem : NULL;
}


__weak_inline__ void list_swap(list_t *from, list_t *to) {
	size_t temp;

	if (!from || !to) {
		hinternal();
	}

	if (from == to) {
		return;
	}

	temp = to->size;
	to->size = from->size;
	from->size = temp;

	to->first = from->first;
	from->first = NULL;

	to->last = from->last;
	from->last = NULL;
}


__strong_inline__ list_node_t *list_push_first(list_t *list, void *elem) {
	if (!list) {
		hinternal();
	}

	return list_insert(list, elem, list->first, INSERT_BEFORE);
}


__strong_inline__ list_node_t *list_push_last(list_t *list, void *elem) {
	if (!list) {
		hinternal();
	}

	return list_insert(list, elem, list->last, INSERT_AFTER);
}


__strong_inline__ void *list_pop_first(list_t *list) {
	if (!list) {
		hinternal();
	}

	return list_remove(list, list->first);
}


__strong_inline__ void *list_pop_last(list_t *list) {
	if (!list) {
		hinternal();
	}

	return list_remove(list, list->last);
}


/************************************************************
*   Balanced binary search tree (AVL tree)
************************************************************/

/// A binary search tree node
// TODO: Possibly add `visited` like we do for graphs
typedef struct bst_node {
	unsigned int id;          /// Unique identifier
	void *elem;               /// Node payload

	size_t height;            /// Height of the sub-tree rooted at this node
	signed char balance;      /// Balance factor of the sub-tree rooted at this node

	struct bst_node *parent;  /// Parent node (if any)
	struct bst_node *left;    /// Left child node (if any)
	struct bst_node *right;   /// Right child node (if any)
} bst_node_t;


/// A binary search tree
typedef struct bst {
	bst_node_t *root;         /// Root node

	size_t size;              /// Total number of nodes
} bst_t;


/// How to visit a binary search tree
typedef enum {
	BST_DEPTH_FIRST,          /// Go vertical, then go horizontal
	BST_BREADTH_FIRST         /// Go horizontal, then go vertical
} bst_visit_policy;


/// Custom visit function for the currently-visited node.
/// `node` is the node which is subject to this visit.
/// `payload` is a pointed to additional user data which is
/// transparently passed from one visit to another to perform
/// any desired side-effect.
typedef bool (*bst_visit_func)(bst_node_t *node, void *payload);


/// Complex object which affects the behavior of a traversal.
// TODO: Possibly add `visited` like we do for graphs
typedef struct {
	void *payload;             /// User data passed to each single visit
	list_t scheduled;          /// Only used internally, must be initialized as empty

	bst_visit_policy policy;   /// How to visit a binary search tree
	bst_visit_func pre_func;   /// Custom pre-visit function
	bst_visit_func in_func;    /// Custom in-visit function
	bst_visit_func post_func;  /// Custom post-visit function
} bst_visit_kernel;


/// Custom comparison function for the currently-visited `node`.
/// `a` and `b` are the nodes which are subject to comparison.
/// `payload` is a pointed to additional user data which is
/// transparently passed from one visit to another to perform
/// any desired side-effect.
typedef char (*bst_compare_func)(void *a, void *b, void *payload);


/// Complex object which affects the behavior of a search.
typedef struct {
	void *payload;                  /// User data passed to each single visit
	bst_compare_func compare_func;  /// Custom comparison function
} bst_search_kernel;


/**
 * Creates a new tree.
 */
__strong_inline__ bst_t *bst_create(void) {
	bst_t *bst;

	bst = hcalloc(sizeof(bst_t));
	return bst;
}


/**
 * Searches for a given payload carried by the tree.
 */
bst_node_t *bst_search(bst_t *tree, void *elem, bst_search_kernel *kernel);


/**
 * Inserts a new payload in the tree.
 */
bst_node_t *bst_insert(bst_t *tree, void *elem, bst_search_kernel *kernel);


/**
 * Performs a complete traversal of the tree.
 */
void bst_visit(bst_node_t *node, bst_visit_kernel *kernel);


/************************************************************
*   Graph
************************************************************/


/// A graph node
typedef struct graph_node {
	unsigned int id;           /// Unique identifier
	unsigned long label;       /// Node label
	void *elem;                /// Node payload

	bool visited;              /// True if the node has already been visited
	bool active;               /// True if the node belongs to the active path

	list_t out;                /// Doubly-linked list of destination nodes
	list_t in;                 /// Doubly-linked list of source nodes
} graph_node_t;


/// A graph edge
typedef struct graph_edge {
	unsigned long label;       /// Edge label

	graph_node_t *from;        /// Source node
	graph_node_t *to;          /// Destination node
} graph_edge_t;


/// A graph
typedef struct {
	list_t sources;            /// Doubly-linked list of sources
	list_t sinks;              /// Doubly-linked list of sinks

	size_t numnodes;           /// Total number of nodes
	size_t numedges;           /// Total number of edges

	bool undirected;           /// True if undirected
} graph_t;


/// How to visit a graph
typedef enum {
	GRAPH_VISIT_DEPTH,         /// Go vertical, then go horizontal
	GRAPH_VISIT_BREADTH        /// Go horizontal, then go vertical
} graph_visit_policy;


/// In which direction to visit a graph
typedef enum {
	GRAPH_VISIT_FORWARD,
	GRAPH_VISIT_BACKWARD
} graph_visit_dir;


/// Custom visit function for the currently-visited node.
/// `node` is the node which is subject to this visit.
/// `payload` is a pointed to additional user data which is
/// transparently passed from one visit to another to perform
/// any desired side-effect.
typedef bool (*graph_visit_func)(void *elem, void *data);


/// Complex object which affects the behavior of a traversal.
typedef struct {
	void *payload;                  /// User data passed to each single visit
	list_t scheduled;               /// Only used internally, must be initialized as empty
	list_t visited;                 /// Only used internally, must be initialized as empty

	graph_visit_policy policy;      /// How to visit a graph
	graph_visit_dir dir;            /// In which direction to visit a graph
	graph_visit_func pre_func;      /// Custom pre-visit function
	graph_visit_func post_func;     /// Custom post-visit function
} graph_visit_kernel;


/// Creates a new graph
__strong_inline__ graph_t *graph_create(void) {
	graph_t *graph;

	graph = hcalloc(sizeof(graph_t));
	return graph;
}


/**
 * Inserts a new payload in the graph.
 */
graph_node_t *graph_insert(graph_t *graph, void *elem, unsigned long label);


/**
 * Connects two nodes in the graph.
 */
graph_edge_t *graph_connect(graph_t *graph, graph_node_t *from,
                            graph_node_t *to, unsigned long label);


__blind__ void *graph_remove(graph_t *graph, graph_node_t *node);


__blind__ void graph_disconnect(graph_t *graph, graph_node_t *from, graph_node_t *to);


/**
 * Performs a complete traversal of the graph.
 */
void graph_visit(graph_t *graph, graph_visit_kernel *kernel);


#endif /* _STRUCTS_H_ */
