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
* @file function.c
* @brief Module to handle functions in the IBR
* @author Simone Economo
*/

#include <string.h>
#include <strings.h>

#include <hijacker.h>
#include <prints.h>
#include <ibr.h>


static weak_inline int compare_common(size_t a_left, size_t a_right,
                                      size_t b_left, size_t b_right) {
	if (a_right <= b_left) {
		return b_left - a_right;
	}
	else if (b_right <= a_left) {
		return b_right - a_left;
	}
	else {
		hinternal();
	}
}


static int block_compare(blk_t *a, blk_t *b, addr_t *address) {
	size_t a_left, a_right, b_left, b_right;

	a_left = block_first_instr(a)->offset;
	a_right = block_last_instr(a)->offset;

	if (!address) {
		b_left = block_first_instr(b)->offset;
		b_right = block_last_instr(b)->offset;
	} else {
		b_left = b_right = *address;
	}

	return compare_common(a_left, a_right, b_left, b_right);
}


static int function_compare(fun_t *a, fun_t *b, addr_t *address) {
	size_t a_left, a_right, b_left, b_right;

	a_left = function_first_instr(a)->offset;
	a_right = function_last_instr(a)->offset;

	if (!address) {
		b_left = function_first_instr(b)->offset;
		b_right = function_last_instr(b)->offset;
	} else {
		b_left = b_right = *address;
	}

	return compare_common(a_left, a_right, b_left, b_right);
}


fun_t *function_insert(list_range_t *instructions, sym_t *symbol) {
	fun_t *function;
	ins_t *instr;

	list_node_t *node;

	if (!range_valid(instructions) || !symbol) {
		hinternal();
	}

	// TODO: Handle function aliases and overlapping functions

	// Populate the new function descriptor
	function = hcalloc(sizeof(fun_t));

	function->symbol = symbol;

	// Insert descriptor in the function chain
	function->node = list_push_last(&__VERSION__(functions), function);

	// Create a new FCG node
	function->fcgnode = graph_insert(&__VERSION__(fcg), function, 0L);

	// Create CFG for this function
	function_parse(function, instructions);

	// We maintain a balanced tree of functions for fast lookup
	// bst_search_kernel kernel = {
	// 	.payload      = NULL,
	// 	.compare_func = &function_compare
	// };

	// bst_insert(&section->index.functions, function, &kernel);

	// Update symbol size
	list_for_each(&instructions, node) {
		instr = node->elem;
		symbol->size += instr->length;
	}

	// Update section symbol size
	symbol->section->symbol->size += symbol->size;

	// Link function descriptor with function symbol descriptor in IBR
	symbol->isa.function = function;

	return function;
}


void function_remove(fun_t *function) {
	if (!function) {
		hinternal();
	}

	// Remove descriptor from the function chain
	list_remove(&__VERSION__(functions), function->node);

	// Remove the FCG node
	graph_remove(&__VERSION__(fcg), function->fcgnode);

	// Update section symbol size
	function->symbol->section->symbol->size += function->symbol->size;

	// TODO: Remove function symbol
	// TODO: Remove all blocks contained in this function
	// TODO: Remove all call instructions to this function

	// Deallocate function descriptor, which is no longer valid
	free(function);
}


fun_t *function_find_byaddr(addr_t address, sec_t *section) {
	list_node_t *node;
	fun_t *function;

	if (!section) {
		hinternal();
	}

	list_for_each(&section->has.functions, node) {
		function = node->elem;

		if (function_first_instr(function)->offset > address) {
			return prev;
		}

		prev = function;
	}

	return NULL;

	// bst_search_kernel kernel = {
	// 	.payload      = &address,
	// 	.compare_func = &function_compare
	// };

	// return bst_search(&section->index.functions, NULL, &kernel);
}


fun_t *function_find_byname(const char *name) {
	sym_t *symbol;

	symbol = symbol_find_byname(name);

	if (symbol) {
		return symbol->isa.function;
	}

	return NULL;
}


static blk_t *block_insert(fun_t *function, list_range_t instructions, blk_t *pivot) {
	blk_t *block;

	// Make room for a new block descriptor
	block = hcalloc(sizeof(blk_t));

	// Fill block descriptor fields
	block->function = function;
	block->instructions = instructions;

	// Insert the descriptor into the block chain
	block->node = list_insert(&__VERSION__(blocks), block, pivot, INSERT_AFTER);

	// Create a new CFG node
	block->cfgnode = graph_insert(&function->cfg, block, 0L);

	// We maintain a balanced tree of blocks for fast lookup
	// TODO: Check that is it correct to do it here...
	// bst_search_kernel kernel = {
	// 	.payload      = NULL,
	// 	.compare_func = &block_compare
	// };

	// bst_insert(&function->index.blocks, right, &kernel);

	return block;
}


static void block_remove(fun_t *function, blk_t *block) {
	// TODO: To implement
}


blk_t *block_find_byaddr(addr_t address, fun_t *function) {
	list_node_t *node;
	blk_t *block;

	if (!function) {
		hinternal();
	}

	list_for_each(&functions->blocks, node) {
		block = node->elem;

		if (function_first_instr(block)->offset > address) {
			return prev;
		}

		prev = block;
	}

	return NULL;

	// bst_search_kernel kernel = {
	// 	.payload      = &address,
	// 	.compare_func = &block_compare
	// };

	// return bst_search(&function->index.blocks, NULL, &kernel);
}


static blk_t *block_split(fun_t *function, blk_t *left,
                          isn_t *breakpoint, blk_split_mode_t mode) {
	blk_t *right;
	isn_t *from;

	list_node_t *incoming, *outgoing;
	graph_edge_t *incoming_edge, *outgoing_edge;

	// If the block is already split at the desired breakpoint
	// just return it unchanged
	if (block_first_instr(left) == breakpoint && mode == SPLIT_FIRST) {
		return left;
	}

	if (block_last_instr(left) == breakpoint && mode == SPLIT_LAST) {
		return left;
	}

	// Compute the new instruction range for the two blocks
	if (mode == SPLIT_FIRST) {
		from = breakpoint->node;
		left->instructions.last = breakpoint->node->prev;
	}
	else if (mode == SPLIT_LAST) {
		from = breakpoint->node->next;
		left->instructions.last = breakpoint->node;
	}

	// Create the new right block
	right = block_insert(function, range(from, left->instructions.last), left);

	// The new block gets all the outgoing connections of the old one
	list_swap(&left->cfgnode.out, &right->cfgnode.out);

	// The outgoing blocks get their incoming connections updated too
	// NOTE: It could be done using graph_* functions, though less
	// efficiently.
	list_for_each(&right->cfgnode.out, outgoing) {
		outgoing_edge = outgoing->elem;

		list_for_each(&(outgoing_edge->to->in), incoming) {
			incoming_edge = incoming->elem;

			if (incoming_edge->from == left) {
				incoming_edge->from = right;
			}
		}
	}

	return right;
}


static weak_inline void block_link(fun_t *function, blk_t *from, blk_t *to,
                                   cfg_edge_label label) {
	if (!from || !to) {
		hinternal();
	}

	if (from == to) {
		return;
	}

	// Connect the two nodes in the CFG
	graph_connect(&function->cfg, from->cfgnode, to->cfgnode, label)
}


static weak_inline blk_t *function_update_cfg(fun_t *function, blk_t *block, isn_t *instr) {
	blk_t *new, *temp, *temp_new;
	isn_t *target;

	if (instr->to.jumptable.size == 0) {
		// A jump must have at least one target instruction,
		// otherwise something is wrong...
		hinternal();
	}
	else if (IS_JUMP(instr) && instr->to.jumptable.size > 1) {
		// It shouldn't ever happen that a direct jump has
		// multiple landing sites...
		hinternal();
	}

	// Split the block along the jump instruction
	new = block_split(function, block, instr, SPLIT_LAST);

	// For each target instruction, perform other split operations
	list_for_each(&(instr->to.jumptable), node) {
		target = node->elem;

		// Find the block containing the target instruction and
		// split it along the latter
		temp = block_find(target);
		temp_new = block_split(function, temp, target, SPLIT_FIRST);

		// If the instruction *before* the target one is not a jump,
		// then it is a labeled instruction and there's no flow control
		// hijacking between the two resulting blocks. For this reason,
		// they must be explicitly connected.
		if (!IS_JUMP(target->prev)) {
			block_link(temp, temp_new, EDGE_FORCED);
		}

		// Link the current block with the one holding the (possibly
		// indirect) destination instruction
		if (IS_JUMPIND(instr)) {
			block_link(block, temp, EDGE_IND);
		} else {
			block_link(block, temp, IS_CONDITIONAL(instr) ? EDGE_THEN : EDGE_GOTO);

			// Conditional jumps can branch into the block next to the
			// current one, therefore we need to connect them
			if (IS_CONDITIONAL(instr)) {
				block_link(block, new, EDGE_ELSE);
			}
		}
	}

	// Return the next block to look at, following the chain of
	// instructions that make up the function
	return new;
}


static weak_inline void function_update_fcg(fun_t *function, blk_t *block, isn_t *instr) {
	sec_t *section;
	fun_t *callee;

	if (IS_CALL(instr) && instr->to.calltable.size > 1) {
		// It shouldn't ever happen that a direct call has
		// multiple landing sites...
		hinternal();
	}

	// Split the block along the call instruction
	new = block_split(function, block, instr, SPLIT_LAST);

	// We don't follow blocks belonging to other functions
	block_link(block, new, EDGE_CALLRET);

	if (instr->to.calltable.size == 0) {
		// We skip function declarations that don't have an actual
		// definition in our relocatable object
		// TODO: Improve check of local vs. undefined functions

		return;
	}

	// For each target instruction, update the FCG
	list_for_each(&(instr->to.calltable), node) {
		target = node->elem;

		// Find the function containing the target instruction
		section = function->symbol->section;
		callee = function_find_byinstr(target, section);

		if (callee) {
			// We're reaching a local function: connect the two function
			// nodes in the Function-Call Graph
			graph_connect(&__VERSION__(fcg), function->fcgnode, callee->fcgnode,
				IS_CALLIND(instr) ? EDGE_CALL_WEAK : EDGE_CALL_STRONG);
		}
	}

	return new;
}


static bool function_complete_cfg_pre(void *elem, void *data) {
	graph_edge_t *edge = elem;

	// If a node is already visited and is part of the current path,
	// then we've identified a loop, therefore the nodes at the two
	// opposite ends of the current edge are respectively the loop
	// header and loop footer
	if (edge->to->visited == true && edge->to->active == true) {
		edge->dir = EDGE_BACK;
		edge->to->label = BLOCK_LOOP_HEADER;
		edge->from->label = BLOCK_LOOP_FOOTER;
	} else {
		edge->dir = EDGE_NEXT;
	}

	if (edge->to->visited == false) {
		// This node becomes part of the current path since we're starting to
		// explore its successor nodes
		edge->to->active = true;
	}

	return true;
}


static bool function_complete_cfg_post(void *elem, void *data) {
	graph_edge_t *edge = elem;

	// If we're leaving the current node, all paths in which it
	// participates have been visited, so we remove it from the current path
	edge->to->active = false;

	return true;
}


void function_parse(fun_t *function, list_range_t instructions) {
	blk_range_t blocks;

	list_node_t *blk_node, *isn_node;

	blk_t *block;
	isn_t *instr;

	size_t blk_length, fun_length;

	if (function == NULL || !range_valid(instructions)) {
		return;
	}

	// TODO: Handle function aliases and overlapping functions
	// TODO: We could have a jump to a non-local function
	// TODO: Perform new visit to the Function-Call Graph?

	// 1. Infer Control-Flow Graph and update Function-Call Graph
	// ------------------------------------------------------------

	// The first block comprises the entire function, but it will be
	// progressively split until we obtain basic blocks
	block = first = block_insert(function, instructions, NULL);

	// Scan the entire instruction chain, looking for breakpoints
	// that can progressively split blocks into smaller chunks.
	// Observe that this is a splitting algorithm, since we start
	// with the biggest block until we obtain maximal basic blocks.
	// An alternative would have been a merging algorithm which
	// creates a minimal block for each instructions, then merges
	// adjacent ones on non-breaking points.
	list_for_each(&instructions, isn_node) {
		instr = isn_node->elem;

		if (instr->offset > block->instructions.last->offset) {
			// We've moved to a block which was already created during
			// a previous iteration
			block = block->next;

			// Every instruction of the program must be mapped to its
			// own block, otherwise we complain
			if (block == NULL) {
				hinternal();
			}
		}

		// Check for jump breakpoints: if indirect jump, we create
		// as many links in the Control-Flow Graph as the number of
		// detected targets; if direct jump, simply link the blocks
		// containing the jump and its target in the Control-Flow Graph
		// --------------------------------------------------------

		if (IS_JUMPIND(instr) || IS_JUMP(instr)) {
			block = function_update_cfg(function, block, instr);
		}

		// Check for call breakpoints: if indirect call, we create
		// as many links in the Function-Call Graph as the number of
		// detected targets; if direct call, simply link the functions
		// containing the call and its target in the Function-Call Graph
		// --------------------------------------------------------

		else if (IS_CALLIND(instr) || IS_CALL(instr)) {
			block = function_update_fcg(function, block, instr);
		}

		// Reverse linking between blocks and instructions
		instr->block = block;
	}

	function->blocks = blk_range(first, block);

	// 2. Infer program loops in the Control-Flow Graph
	// ------------------------------------------------------------

	graph_visit_kernel kernel = {
		.payload   = NULL,
		.policy    = GRAPH_VISIT_DEPTH,
		.dir       = GRAPH_VISIT_FORWARD,
		.pre_func  = function_complete_cfg_pre,
		.post_func = function_complete_cfg_post
	};

	graph_visit(&__VERSION__(cfg), &kernel);

	// 3. Compute function and block lengths
	// ------------------------------------------------------------

	fun_length = 0;

	list_for_each(&function->blocks, blk_node) {
		block = blk_node->elem;
		blk_length = 0;

		list_for_each(&block->instructions, isn_node) {
			instr = ins_node->elem;
			blk_length += 1;
		}

		block->length = blk_length;
		fun_length += 1;
	}

	function->length = fun_length;
}
