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
* @file block.c
* @brief Structures and functions to handle basic blocks
* @author Simone Economo
* @date June 18, 2015
*/

#include <prints.h>
#include <executable.h>

static block *root = NULL;

#define TREEDUMP_FILE   "treedump.txt"
#define GRAPHDUMP_FILE  "graphdump.txt"

block *block_create() {
  block *blk;
  static int id;

  blk = calloc(sizeof(block), 1);
  blk->id = ++id;

  // This is a bit of an ugly hack, but is functional to
  // avoiding polluting the namespace with a global symbol
  // or having to pass a variable to all visible functions
  // of this module
  // TODO: Devise a better mechanism which is unit-test friendly
  if (!root) {
    root = blk;
  }

  return blk;
}

static void block_tree_balance_update(block *blk) {
  unsigned int left_height, right_height;

  left_height = right_height = 0;

  if (blk->left) {
    left_height = blk->left->height;
  }
  if (blk->right) {
    right_height = blk->right->height;
  }

  blk->height = (left_height > right_height ? left_height : right_height) + 1;
  blk->balance = left_height - right_height;
}

static void block_tree_replace(block *replaced, block *replacement) {
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

static void block_tree_rotate_left(block **parent, block **child) {
  block *temp;

  // 'parent' becomes the left block of the one denoted 'child'

  block_tree_replace(*parent, *child);

  (*parent)->parent = (*child);
  (*parent)->right = (*child)->left;

  if ((*parent)->right) {
    (*parent)->right->parent = (*parent);
  }

  (*child)->left = (*parent);

  block_tree_balance_update(*parent);
  block_tree_balance_update(*child);

  temp = *parent, *parent = *child, *child = temp;
}

static void block_tree_rotate_right(block **parent, block **child) {
  block *temp;

  // 'parent' becomes the right block of the one denoted 'child'

  block_tree_replace(*parent, *child);

  (*parent)->parent = (*child);
  (*parent)->left = (*child)->right;

  if ((*parent)->left) {
    (*parent)->left->parent = (*parent);
  }

  (*child)->right = (*parent);

  block_tree_balance_update(*parent);
  block_tree_balance_update(*child);

  temp = *parent, *parent = *child, *child = temp;
}

static void block_tree_rebalance(block *orig, block *new) {
  block *parent, *first, *second, *temp;

  // Node insertion: the right-most block replaces the original
  // and the latter becomes the left child of the former
  block_tree_replace(orig, new);

  orig->parent = new;
  new->left = orig;
  new->right = orig->right;

  if (new->right) {
    new->right->parent = new;
  }

  orig->right = NULL;

  // We now check if there's need to re-balance the tree
  // and at the same time we recompute all balance factors
  // that have changed since the latest insertion
  parent = orig;
  first = orig->left;
  second = (first ? first->left : NULL);

  while (parent) {
    block_tree_balance_update(parent);
    hnotice(3, "Checking whether block #%u needs re-balancing (balance %d)\n", parent->id, parent->balance);

    if (parent->balance == 2) {
      // LEFT RIGHT case
      if (first->balance == -1) {
        hnotice(4, "Re-balancing block #%u, LEFT RIGHT case\n", parent->id);
        block_tree_rotate_left(&first, &second);
      }
      // LEFT LEFT case
      hnotice(4, "Re-balancing block #%u, LEFT LEFT case\n", parent->id);
      block_tree_rotate_right(&parent, &first);
    }

    else if (parent->balance == -2) {
      // RIGHT LEFT case
      if (first->balance == 1) {
        hnotice(4, "Re-balancing block #%u, RIGHT LEFT case\n", parent->id);
        block_tree_rotate_right(&first, &second);
      }
      // RIGHT RIGHT case
      hnotice(4, "Re-balancing block #%u, RIGHT RIGHT case\n", parent->id);
      block_tree_rotate_left(&parent, &first);
    }

    second = first;
    first = parent;
    parent = parent->parent;
  }
}

block *block_find(insn_info *instr) {
  block *blk;

  if (!instr) {
    return NULL;
  }

  blk = root;

  while(blk) {
    if (blk->begin->orig_addr > instr->orig_addr) {
      blk = blk->left;
    }
    else if (blk->end->orig_addr < instr->orig_addr) {
      blk = blk->right;
    }
    else {
      break;
    }
  }

  return blk;
}

block *block_split(block *blk, insn_info *breakpoint, block_split_mode mode) {
  block *new_blk;

  // This covers the cases of the first and last instructions
  // of the entire program
  if (blk->begin == breakpoint && mode == BLOCK_SPLIT_FIRST)
    return blk;
  if (blk->end == breakpoint && mode == BLOCK_SPLIT_LAST)
    return blk;

  // Allocate the new blocks, update the ordered list
  // and appropriately mark their boundaries
  new_blk = block_create();
  new_blk->next = blk->next;
  blk->next = new_blk;

  if (mode == BLOCK_SPLIT_FIRST) {
    new_blk->begin = breakpoint;
    new_blk->end = blk->end;
    blk->end = breakpoint->prev;
  }
  else if (mode == BLOCK_SPLIT_LAST) {
    new_blk->begin = breakpoint->next;
    new_blk->end = blk->end;
    blk->end = breakpoint;
  }
  else {
    hinternal();
  }

  // The new block gets all the outgoing connections of the old one
  // The outgoing blocks get their incoming connections updated too
  ll_move(&(blk->out), &(new_blk->out));

  ll_node *outgoing, *incoming;
  block *outgoing_blk, *incoming_blk;

  outgoing = new_blk->out.first;
  while(outgoing) {
    outgoing_blk = outgoing->elem;

    incoming = outgoing_blk->in.first;
    while (incoming) {
      incoming_blk = incoming->elem;

      if (incoming_blk == blk) {
        incoming->elem = new_blk;
      }

      incoming = incoming->next;
    }

    outgoing = outgoing->next;
  }

  hnotice(3, "Block splitting result: #%u from <%#08llx> to <%#08llx>, "
    "#%u from <%#08llx> to <%#08llx>\n",
    blk->id, blk->begin->orig_addr, blk->end->orig_addr,
    new_blk->id, new_blk->begin->orig_addr, new_blk->end->orig_addr);

  // We maintain a balanced tree of blocks for fast lookup
  block_tree_rebalance(blk, new_blk);

  return new_blk;
}

void block_link(block *from, block *to) {
  linked_list *out, *in;

  if (from == to) {
    hnotice(3, "Skipping block #%u auto-linking\n", from->id, to->id);
    return;
  }

  hnotice(3, "Linking block #%u with block #%u\n", from->id, to->id);

  out = &(from->out);
  in = &(to->in);

  // Connect source to destination
  ll_push(out, to);

  // Connect destination to source
  ll_push(in, from);
}

void block_tree_print() {
  FILE *f;
  block *blk;
  linked_list *queue, *queue_temp;

  f = fopen(TREEDUMP_FILE, "w+");

  queue = calloc(sizeof(linked_list), 1);
  queue_temp = calloc(sizeof(linked_list), 1);

  if (!root) {
    return NULL;
  }

  ll_push(queue, root);

  while(true) {

    while(!ll_empty(queue)) {
      blk = ll_pop_first(queue);

      fprintf(f, "Block #%u from <%#08llx> to <%#08llx> has balance %d, "
        "left #%u, right #%u and parent #%u\n",
        blk->id, blk->begin->orig_addr, blk->end->orig_addr, blk->balance,
        (blk->left ? blk->left->id : 0),
        (blk->right ? blk->right->id : 0),
        (blk->parent ? blk->parent->id : 0));

      if (blk->left) {
        ll_push(queue_temp, blk->left);
      }
      if (blk->right) {
        ll_push(queue_temp, blk->right);
      }
    }

    if (ll_empty(queue_temp)) {
      break;
    }

    ll_move(queue_temp, queue);
  }

  free(queue);
  free(queue_temp);

  fclose(f);
}

void block_graph_print(block *start) {
  FILE *f;
  block *current_blk, *temp_blk;
  ll_node *to_node, *from_node;

  f = fopen(GRAPHDUMP_FILE, "w+");

  current_blk = start;
  while(current_blk) {
    to_node = current_blk->out.first;
    from_node = current_blk->in.first;

    fprintf(f, "Block #%u", current_blk->id);

    if (to_node) {
      fprintf(f, " links to");

      while(to_node) {
        temp_blk = to_node->elem;
        fprintf(f, " #%u", temp_blk->id);

        to_node = to_node->next;
      }

    }

    if (from_node) {
      fprintf(f, " reached from");

      while(from_node) {
        temp_blk = from_node->elem;
        fprintf(f, " #%u", temp_blk->id);

        from_node = from_node->next;
      }

    }

    fprintf(f, "\n");

    current_blk = current_blk->next;
  }
}
