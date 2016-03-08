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
* @file structs.c
* @brief Basic data structures
* @author Simone Economo
*/

#include <stdio.h>
#include <stdlib.h>

#include <utils.h>
#include <prints.h>
#include <structs.h>


/************************************************************
*   Doubly-linked list
************************************************************/

void list_push(list_t *list, void *elem) {
	list_node_t *node;

	node = hcalloc(sizeof(list_node_t));
	node->elem = elem;

	if (list_empty(list)) {
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

void list_push_first(list_t *list, void *elem) {
	list_node_t *node;

	node = hcalloc(sizeof(list_node_t));
	node->elem = elem;

	if (list_empty(list)) {
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

void *list_pop(list_t *list) {
	list_node_t *node;
	void *elem;

	if (!list_empty(list)) {
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

void *list_pop_first(list_t *list) {
	list_node_t *node;
	void *elem;

	if (!list_empty(list)) {
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


/************************************************************
*   Balanced binary search tree (AVL tree)
************************************************************/

/**
 * Updates the height and the balance factor of a given tree node.
 *
 * @param node Pointer to the tree node which must be updated.
 */
weak_inline static void bst_balance_update(bst_node_t *node) {
	unsigned int left_height, right_height;

	// left_height = right_height = 0;

	// if (node->left) {
		left_height = node->left->height;
	// }
	// if (node->right) {
		right_height = node->right->height;
	// }

	node->height = (left_height > right_height ? left_height : right_height) + 1;
	node->balance = left_height - right_height;
}


/**
 * Replaces one tree node with another, making sure that the
 * coherence of vertical linkage is preserved.
 *
 * @param replaced Pointer to the tree node which must be replaced.
 * @param replacement Pointer to the new tree node.
 */
weak_inline static void bst_parent_update(bst_node_t *replaced, bst_node_t *replacement) {
	replacement->parent = replaced->parent;

	if (!replaced->parent) {
		root = replacement;
	}
	else if (replaced->parent->left == replaced) {
		replaced->parent->left = replacement;
	}
	else {
		replaced->parent->right = replacement;
	}
}


/**
 * Rotates the parent node to the left of the child node, adjusting
 * their relationship within the tree.
 *
 * For example, given the following input situation:
 *
 *                            5
 *                    +---------------+
 *                    3               D
 *                +-------+
 *                A       4
 *                      +---+
 *                      B   C
 *
 * The resulting tree after applying left-rotation to (3, 4) is:
 *
 *                            5
 *                    +---------------+
 *                    4               D
 *                +-------+
 *                3       C
 *              +---+
 *              A   C
 *
 * Observe that this function overwrites the pointers passed
 * as arguments to reflect the linkage inversion.
 *
 * @param parent Double pointer to the parent node.
 * @param child Double pointer to the child node.
 */
weak_inline static void bst_rotate_left(bst_node_t **parent, bst_node_t **child) {
	bst_node_t *temp;

	// 'parent' becomes the left block of the one denoted 'child'
	bst_parent_update(*parent, *child);

	(*parent)->parent = (*child);
	(*parent)->right = (*child)->left;

	// if ((*parent)->right) {
		(*parent)->right->parent = (*parent);
	// }

	(*child)->left = (*parent);

	bst_balance_update(*parent);
	bst_balance_update(*child);

	temp = *parent, *parent = *child, *child = temp;
}


/**
 * Rotates the parent node to the right of the child node, adjusting
 * their relationship within the tree.
 *
 * For example, given the following input situation:
 *
 *                            3
 *                    +---------------+
 *                    A               5
 *                                +-------+
 *                                4       D
 *                              +---+
 *                              B   C
 *
 * The resulting tree after applying right-rotation to (5, 4) is:
 *
 *                            3
 *                    +---------------+
 *                    A               4
 *                                +-------+
 *                                B       5
 *                                      +---+
 *                                      C   D
 *
 * Observe that this function overwrites the pointers passed
 * as arguments to reflect the linkage inversion.
 *
 * @param parent Double pointer to the parent node.
 * @param child Double pointer to the child node.
 */
weak_inline static void bst_rotate_right(bst_node_t **parent, bst_node_t **child) {
	bst_node_t *temp;

	// 'parent' becomes the right block of the one denoted 'child'
	bst_parent_update(*parent, *child);

	(*parent)->parent = (*child);
	(*parent)->left = (*child)->right;

	// if ((*parent)->left) {
		(*parent)->left->parent = (*parent);
	// }

	(*child)->right = (*parent);

	bst_balance_update(*parent);
	bst_balance_update(*child);

	temp = *parent, *parent = *child, *child = temp;
}


/**
 * Balances the entire tree starting from the tree node passed
 * as input, and ramps up the tree until no more balancing is
 * needed.
 *
 * Observe that re-balancing occurs if the modulo balance factor
 * of the tree is > 1. In that case, it applies a series of
 * rotations to the tree in order to ensure that all nodes have
 * a modulo balance factor which is in the range [0,1].
 *
 * For example, given the following input situation:
 *
 *                            5
 *                    +---------------+
 *                    3               D
 *                +-------+
 *                A       4
 *                      +---+
 *                      B   C
 *
 * The resulting tree after applying re-balancing to (4) is:
 *
 *                            4
 *                    +---------------+
 *                    3               5
 *                +-------+       +-------+
 *                A       B       C       D
 *
 * @param node Pointer to the base node from which re-balancing begins.
 */
static void bst_rebalance(bst_node_t *node) {
	block *parent, *first, *second;

	parent = node;
	first = second = NULL;

	while (parent) {
		// We recompute all balance factors that have changed
		// since the last insertion, prior to performing the
		// re-balancing
		bst_balance_update(parent);

		if (parent->balance >= 2) {
			// LEFT RIGHT case
			if (first->balance <= -1) {
				second = first->right;
				bst_rotate_left(&first, &second);
			}

			// LEFT LEFT case
			bst_rotate_right(&parent, &first);
		}

		else if (parent->balance <= -2) {
			// RIGHT LEFT case
			if (first->balance >= 1) {
				second = first->left;
				bst_rotate_right(&first, &second);
			}

			// RIGHT RIGHT case
			bst_rotate_left(&parent, &first);
		}

		second = first;
		first = parent;
		parent = parent->parent;
	}
}


/**
 * Searches for a given payload carried by the tree.
 *
 * @param tree Pointer to the tree that acts as the haystack.
 * @param elem Pointer to the payload that acts as the needle.
 * @param kernel Pointer to a kernel object which drives the search.
 */
bst_node_t *bst_search(bst_t *tree, void *elem, bst_search_kernel *kernel) {
	bst_node_t *current;
	char where;

	if (tree == NULL || elem == NULL || kernel == NULL) {
		hinternal();
	}
	else if (kernel->compare_func == NULL) {
		hinternal();
	}

	current = tree->root;

	while (current->elem != NULL) {
		where = kernel->compare_func(current->elem, elem, kernel->payload);

		if (where == 0) {
			break;
		}
		else if (where < 0) {
			current = current->left;
		}
		else {
			current = current->right;
		}
	}

	return current;
}


/**
 * Inserts a new payload in the tree.
 *
 * Observe that internally, a search is performed to seek the precise
 * position at which the new node must be inserted.
 *
 * @param tree Pointer to the tree.
 * @param elem Pointer to the payload.
 * @param kernel Pointer to a kernel object which drives the insertion.
 *
 * @return Pointer to the newly-inserted node, or NULL if a node is
 *         already present at the requested position.
 */
bst_node_t *bst_insert(bst_t *tree, void *elem, bst_search_kernel *kernel) {
	static unsigned id;
	bst_node_t *found;

	if (tree == NULL || elem == NULL || kernel == NULL) {
		hinternal();
	}

	if (tree->root == NULL) {
		found = tree->root = hcalloc(sizeof(bst_node_t));
	} else {
		found = bst_search(tree, elem, kernel);
	}

	if (found->elem != NULL) {
		return NULL;
	}

	found->left = hcalloc(sizeof(bst_node_t));
	found->right = hcalloc(sizeof(bst_node_t));
	found->elem = elem;
	found->id = ++id;

	tree->size += 1;

	bst_rebalance(found);

	return found;
}


/**
 * Performs the next visit to the tree. More specifically, it invokes
 * all visit functions provided by the kernel, at the appropriate
 * points. Then, it schedules visits to the current node's children.
 * If the current node is empty or one of the *-visit functions
 * returns `false`, no further visits are scheduled from the currently-
 * visited tree node.
 *
 * @param node Pointer to the currently-visited node.
 * @param kernel Pointer to a kernel object which drives the traversal.
 */
static void bst_visit_next(bst_node_t *node, graph_visit_kernel *kernel) {
	bst_node_t *next;

	// Base case: we've reached the end of a tree path
	if (node->elem == NULL) {
		return;
	}

	// Invoke the custom visit function to the currently-visited
	// tree node, as in pre-order/level-order traversal
	if (kernel->pre_func != NULL) {
		if (kernel->pre_func(node, kernel->payload) == false) {
			return;
		}
	}

	// Schedule visits to the node children
	if (node->right->elem != NULL) {
		list_push(&kernel->scheduled, node->right);
	}
	if (node->left->elem != NULL) {
		list_push(&kernel->scheduled, node->left);
	}

	// Pop an element from the schedule according to the desired policy,
	// which logically matches the previous insertion of a left child
	// TODO: Only DEPTH_FIRST is currently supported
	if (kernel->policy == BST_DEPTH_FIRST && node->left->elem != NULL) {
		next = list_pop(&kernel->scheduled);

		bst_visit_next(next, kernel);
	}
	// else if (kernel->policy == BST_BREADTH_FIRST && node->left->elem != NULL) {
	//   next = list_pop_first(&kernel->scheduled);
	// }

	// Invoke the custom visit function to the currently-visited
	// tree node, as in in-order traversal
	if (kernel->in_func != NULL) {
		if (kernel->in_func(node, kernel->payload) == false) {
			return;
		}
	}

	// Pop an element from the schedule according to the desired policy,
	// which logically matches the previous insertion of a right child
	// TODO: Only DEPTH_FIRST is currently supported
	if (kernel->policy == BST_DEPTH_FIRST && node->right->elem != NULL) {
		next = list_pop(&kernel->scheduled);

		bst_visit_next(next, kernel);
	}
	// else if (kernel->policy == BST_BREADTH_FIRST && node->right->elem != NULL) {
	//   next = list_pop_first(&kernel->scheduled);
	// }

	// Invoke the custom visit function to the currently-visited
	// tree node, as in post-order traversal
	if (kernel->post_func != NULL) {
		kernel->post_func(node, kernel->payload);
	}
}


/**
 * Performs a complete traversal of the tree. Depending on the provided
 * kernel, it can perform either a depth-first visit, or a bread-
 * first visit. In the first case, three sub-modes of traversal are
 * supported: pre-order, in-order and post-order. In the second case,
 * only pre-order is supported (also called level-order for bread-
 * first traversal).
 *
 * Observe that the duration of a traversal depends on both the size
 * of the tree, and the return value of the pre-order or in-order
 * visit functions. If one of them returns `false`, the traversal
 * won't schedule any further visits to the current node's children.
 *
 * @param node Pointer to the starting node from which traversal begins.
 * @param kernel Pointer to a kernel object which drives the traversal.
 */
void bst_visit(bst_node_t *node, bst_visit_kernel *kernel) {
	if (node == NULL) {
		hinternal();
	}
	else if (kernel == NULL) {
		hinternal();
	}
	else if (kernel->pre_func == NULL && kernel->in_func == NULL && kernel->post_func == NULL) {
		hinternal();
	}

	// Visit initialization
	list_init(&kernel->scheduled);

	// Starts the visit
	bst_visit_next(node, kernel);
}


/************************************************************
*   Graph
************************************************************/

/**
 * Inserts a new payload in the graph.
 *
 * @param graph Pointer to the graph.
 * @param elem Pointer to the payload.
 * @param label Annotation assigned to the newly-inserted node.
 *
 * @return Pointer to the newly-inserted node.
 */
graph_node_t *graph_insert(graph_t *graph, void *elem, unsigned long label) {
	unsigned int id;

	graph_node_t *node;

	if (graph == NULL || elem == NULL) {
		hinternal();
	}

	node = hcalloc(sizeof(graph_node_t));
	node->label = label;
	node->elem = elem;
	node->id = ++id;

	// Append the newly-created object to the list of nodes
	list_push(&gr->nodes, node);

	gr->numnodes += 1;

	return node;
}

/**
 * Connects two nodes in the graph.
 *
 * @param graph Pointer to the graph.
 * @param from Pointer to the source node.
 * @param to Pointer to the destination node.
 * @param label Annotation assigned to the newly-inserted edge.
 *
 * @return Pointer to the newly-inserted edge.
 */
graph_edge_t *graph_connect(graph_t *graph, graph_node_t *from, graph_node_t *to, unsigned long label) {
	graph_edge_t *edge;

	if (from == NULL || to == NULL) {
		hinternal();
	}

	if (from == to) {
		return;
	}

	edge = hcalloc(sizeof(graph_edge_t));
	edge->label = label;
	edge->from = from;
	edge->to = to;

	// Connect source to destination
	list_push(&from->out, edge);

	// Connect destination to source
	list_push(&to->in, edge);

	// Append the newly-created object to the list of edges
	list_push(&gr->edges, edge);

	gr->numedges += 1;

	hnotice(3, "Linking node #%u with node #%u\n", from->id, to->id);

	return edge;
}


/**
 * Performs the next visit to the graph. More specifically, it invokes
 * all visit functions provided by the kernel, at the appropriate
 * points. Then, it schedules visits to the current node's neighbors.
 * If the current node is empty or the pre-visit function returns `false`,
 * no further visits are scheduled from the currently-visited graph node.
 *
 * @param edge Pointer to the currently-visited edge.
 * @param kernel Pointer to a kernel object which drives the traversal.
 */
static void graph_visit_next(graph_edge_t *edge, graph_visit_kernel *kernel) {
	graph_node_t *node;
	list_node_t *tosched;

	// Base case: we've reached the end of a graph path
	if (node->visited == true) {
		return;
	}

	// Establishes which is the next node to schedule for a visit
	if (kernel->dir == GRAPH_DIR_FORWARD) {
		node = edge->to;
		tosched = node->in.first;
	}
	else if (kernel->dir == GRAPH_DIR_BACKWARD) {
		node = edge->from;
		tosched = node->out.first;
	}

	// Invoke the custom pre-visit function to the currently-visited
	// graph node
	if (kernel->pre_func != NULL) {
		if (kernel->pre_func(edge, kernel->payload) == false) {
			return;
		}
	}

	// The node is marked as visited and inserted into a list of
	// already-visited nodes
	node->visited = true;

	list_push(&kernel->visited, node);

	// A number of visits is invoked which is equal to the fanout
	// of the currently-visited node
	for (; tosched; tosched = tosched->next) {
		list_push(&kernel->scheduled, tosched->elem);

		if (kernel->policy == GRAPH_DEPTH_FIRST) {
			edge = list_pop(&kernel->scheduled);
		}
		else if (kernel->policy == GRAPH_BREADTH_FIRST) {
			edge = list_pop_first(&kernel->scheduled);
		}

		graph_visit_next(edge, kernel);
	}

	// Invoke the custom post-visit function to the currently-visited
	// graph node
	if (kernel->post_func != NULL) {
		kernel->post_func(edge, kernel->payload);
	}
}


/**
 * Performs a complete traversal of the graph. Depending on the provided
 * kernel, it can perform either a depth-first visit, or a bread-
 * first visit. In the first case, two sub-modes of traversal are
 * supported: pre-order and post-order. In the second case,
 * only pre-order is supported (also called level-order for bread-
 * first traversal).
 *
 * Observe that the duration of a traversal depends on both the size
 * of the graph, and the return value of the pre-order visit function
 * If it returns `false`, the traversal won't schedule any further visits
 * to the current node's children.
 *
 * @param edge Pointer to the starting edge from which traversal begins.
 * @param kernel Pointer to a kernel object which drives the traversal.
 */
void graph_visit(graph_edge_t *edge, graph_visit_kernel *kernel) {
	list_t *scheduled, *visited;
	graph_node_t *node;

	// A few sanity checks before running the visit
	if (edge == NULL) {
		hinternal();
	}
	else if (kernel == NULL) {
		hinternal();
	}
	// else if (kernel->policy != GRAPH_BREADTH_FIRST && kernel->policy != GRAPH_DEPTH_FIRST) {
	// 	hinternal();
	// }
	// else if (kernel->dir != GRAPH_DIR_FORWARD && kernel->dir != GRAPH_DIR_BACKWARD) {
	// 	hinternal();
	// }
	else if (kernel->pre_func == NULL && kernel->post_func == NULL) {
		return;
	}

	// Visit initialization
	list_init(&kernel->scheduled);
	list_init(&kernel->visited);

	// Starting the visit
	graph_visit_next(edge, kernel);

	// Clearing the effect of this visit not to hamper future ones
	while (!list_empty(&kernel->visited)) {
		node = list_pop(&kernel->visited);

		node->visited = false;
	}
}

