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


/************************************************************
*   Doubly-linked list
*   TODO: To be possibly replaced with generics
************************************************************/

typedef struct list_node {
	void *elem;
	struct list_node *next;
	struct list_node *prev;
} list_node_t;


typedef struct list {
	size_t size;
	list_node_t *first;
	list_node_t *last;
} list_t;


strong_inline void list_swap(list_t *from, list_t *to) {
	to->first = from->first;
	from->first = NULL;
	to->last = from->last;
	from->last = NULL;
}


strong_inline bool list_empty(list_t *list) {
	return (list->first ? false : true);
}

void list_push(list_t *list, void *elem);
void list_push_first(list_t *list, void *elem);
void *list_pop(list_t *list);
void *list_pop_first(list_t *list);


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
typedef char (*bbs_tree_compare_func)(void *a, void *b, void *payload);


/// Complex object which affects the behavior of a search.
typedef struct {
	void *payload;                  /// User data passed to each single visit
	bst_compare_func compare_func;  /// Custom comparison function
} bst_search_kernel;


/**
 * Creates a new tree.
 */
strong_inline bst_t *bst_create(void) {
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
void bst_visit(bst_t *tree, bst_visit_kernel *kernel);


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
strong_inline graph_t *graph_create(void) {
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
graph_edge_t *graph_connect(graph_node_t *pivot, void *elem);


/**
 * Performs a complete traversal of the graph.
 */
void graph_visit(graph_t *graph, graph_visit_kernel *kernel);
