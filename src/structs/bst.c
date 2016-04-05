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
* @file bst.c
* @brief Balanced binary search tree (AVL tree) functions
* @author Simone Economo
*/

#include <utils.h>
#include <prints.h>
#include <structs/structs.h>


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

  if (!tree || !kernel) {
    hinternal();
  }
  else if (!kernel->compare_func) {
    hinternal();
  }

  current = tree->root;

  while (current->elem) {
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

  if (!tree || !elem || !kernel) {
    hinternal();
  }

  if (!tree->root) {
    found = tree->root = hcalloc(sizeof(bst_node_t));
  } else {
    found = bst_search(tree, elem, kernel);
  }

  if (found->elem) {
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
  if (!node->elem) {
    return;
  }

  // Invoke the custom visit function to the currently-visited
  // tree node, as in pre-order/level-order traversal
  if (kernel->pre_func) {
    if (kernel->pre_func(node, kernel->payload) == false) {
      return;
    }
  }

  // Schedule visits to the node children
  if (node->right->elem) {
    list_push_last(&kernel->scheduled, node->right);
  }
  if (node->left->elem) {
    list_push_last(&kernel->scheduled, node->left);
  }

  // Pop an element from the schedule according to the desired policy,
  // which logically matches the previous insertion of a left child
  // TODO: Only DEPTH_FIRST is currently supported
  if (kernel->policy == BST_DEPTH_FIRST && node->left->elem != NULL) {
    next = list_pop_last(&kernel->scheduled);

    bst_visit_next(next, kernel);
  }
  // else if (kernel->policy == BST_BREADTH_FIRST && node->left->elem != NULL) {
  //   next = list_pop_first(&kernel->scheduled);
  // }

  // Invoke the custom visit function to the currently-visited
  // tree node, as in in-order traversal
  if (kernel->in_func) {
    if (kernel->in_func(node, kernel->payload) == false) {
      return;
    }
  }

  // Pop an element from the schedule according to the desired policy,
  // which logically matches the previous insertion of a right child
  // TODO: Only DEPTH_FIRST is currently supported
  if (kernel->policy == BST_DEPTH_FIRST && node->right->elem) {
    next = list_pop_last(&kernel->scheduled);

    bst_visit_next(next, kernel);
  }
  // else if (kernel->policy == BST_BREADTH_FIRST && node->right->elem != NULL) {
  //   next = list_pop_first(&kernel->scheduled);
  // }

  // Invoke the custom visit function to the currently-visited
  // tree node, as in post-order traversal
  if (kernel->post_func) {
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
  if (!node) {
    hinternal();
  }
  else if (!kernel) {
    hinternal();
  }
  else if (!kernel->pre_func && !kernel->in_func && !kernel->post_func) {
    hinternal();
  }

  // Visit initialization
  list_init(&kernel->scheduled);

  // Starts the visit
  bst_visit_next(node, kernel);
}
