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
#include <ibr.h>

#include <elf/handle-elf.h>

static block *root[MAX_VERSIONS];

block *block_create(void) {
	block *blk;
	static int id;

	blk = calloc(sizeof(block), 1);
	blk->id = ++id;

	// This is a bit of an ugly hack, but is functional to
	// avoiding polluting the namespace with a global symbol
	// or having to pass a variable to all visible functions
	// of this module
	// TODO: Devise a better mechanism which is unit-test friendly
	if (!root[PROGRAM(version)]) {
		root[PROGRAM(version)] = blk;
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

static void block_tree_parent_update(block *replaced, block *replacement) {
	replacement->parent = replaced->parent;

	if (!replaced->parent) {
		root[PROGRAM(version)] = replacement;
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

	block_tree_parent_update(*parent, *child);

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

	block_tree_parent_update(*parent, *child);

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
	block *parent, *first, *second;

	// Node insertion: the right-most block replaces the original
	// and the latter becomes the left child of the former
	new->parent = orig;
	new->right = orig->right;
	orig->right = new;

	if (new->right) {
		new->right->parent = new;
	}

	// We now check if there's need to re-balance the tree
	// and at the same time we recompute all balance factors
	// that have changed since the latest insertion
	parent = new;
	first = new->right;

	while (parent) {
		block_tree_balance_update(parent);
		hnotice(6, "Checking whether block #%u needs re-balancing (balance %d)\n", parent->id, parent->balance);

		if (parent->balance >= 2) {
			// LEFT RIGHT case
			if (first->balance <= -1) {
				second = first->right;
				hnotice(5, "Re-balancing block #%u, LEFT RIGHT case\n", parent->id);
				block_tree_rotate_left(&first, &second);
			}
			// LEFT LEFT case
			hnotice(5, "Re-balancing block #%u, LEFT LEFT case\n", parent->id);
			block_tree_rotate_right(&parent, &first);
		}

		else if (parent->balance <= -2) {
			// RIGHT LEFT case
			if (first->balance >= 1) {
				second = first->left;
				hnotice(5, "Re-balancing block #%u, RIGHT LEFT case\n", parent->id);
				block_tree_rotate_right(&first, &second);
			}
			// RIGHT RIGHT case
			hnotice(5, "Re-balancing block #%u, RIGHT RIGHT case\n", parent->id);
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
		hinternal();
	}

	for (blk = PROGRAM(blocks[PROGRAM(version)]); blk; blk = blk->next) {
		if (blk->begin->index <= instr->index & blk->end->index >= instr->index) {
			return blk;
		}
	}

	return NULL;

	// blk = root[PROGRAM(version)];

	// while(blk) {
	// 	if (blk->begin->index > instr->index) {
	// 		blk = blk->left;
	// 	}
	// 	else if (blk->end->index < instr->index) {
	// 		blk = blk->right;
	// 	}
	// 	else {
	// 		break;
	// 	}
	// }

	// return blk;
}

block *block_split(block *blk, insn_info *breakpoint, block_split_mode mode) {
	block *new_blk;

	// If the block is already split at the desired breakpoint
	// just return it
	if (blk->begin == breakpoint && mode == SPLIT_FIRST) {
		return blk;
	}
	if (blk->end == breakpoint && mode == SPLIT_LAST) {
		return blk;
	}

	// Allocate the new blocks, update the ordered list
	// and appropriately mark their boundaries
	new_blk = block_create();
	new_blk->next = blk->next;
	blk->next = new_blk;

	if (mode == SPLIT_FIRST) {
		new_blk->begin = breakpoint;
		new_blk->end = blk->end;
		blk->end = breakpoint->prev;
	}
	else if (mode == SPLIT_LAST) {
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
	block_edge *outgoing_edge, *incoming_edge;

	for (outgoing = new_blk->out.first; outgoing; outgoing = outgoing->next) {
		outgoing_edge = outgoing->elem;

		for (incoming = outgoing_edge->to->in.first; incoming; incoming = incoming->next) {
			incoming_edge = incoming->elem;

			if (incoming_edge->from == blk) {
				incoming_edge->from = new_blk;
			}
		}
	}

	hnotice(4, "Block splitting result: #%u from <%#08llx> to <%#08llx>, "
		"#%u from <%#08llx> to <%#08llx>\n",
		blk->id, blk->begin->orig_addr, blk->end->orig_addr,
		new_blk->id, new_blk->begin->orig_addr, new_blk->end->orig_addr);

	// We maintain a balanced tree of blocks for fast lookup
	// block_tree_rebalance(blk, new_blk);

	return new_blk;
}

void block_link(block *from, block *to, block_edge_type type) {
	linked_list *out, *in;
	block_edge *edge;

	if (from == NULL || to == NULL) {
		hinternal();
	}

	if (from == to) {
		hnotice(4, "Skipping block #%u auto-linking\n", from->id);
		return;
	}

	edge = malloc(sizeof(block_edge));
	edge->type = type;
	edge->from = from;
	edge->to = to;

	out = &(from->out);
	in = &(to->in);

	// Connect source to destination
	ll_push(out, edge);

	// Connect destination to source
	ll_push(in, edge);

	hnotice(4, "Linking block #%u with block #%u\n", from->id, to->id);
}

void block_tree_dump(char *filename, char *mode) {
	FILE *f;
	block *blk;
	linked_list *queue, *queue_temp;

	// FIXME: Disabled for now
	return;

	if (!root[PROGRAM(version)]) {
		return;
	}

	if (!mode) {
		hinternal();
	}

	if (filename) {
		f = fopen(filename, mode);
	} else {
		f = stdout;
	}

	queue = calloc(sizeof(linked_list), 1);
	queue_temp = calloc(sizeof(linked_list), 1);

	ll_push(queue, root[PROGRAM(version)]);

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

	fprintf(f, "\n");

	free(queue);
	free(queue_temp);

	if (filename) {
		fclose(f);
	}
}

static bool block_graph_dump_pre(void *elem, void *data) {
	block_edge *edge;
	block *blk;
	FILE *f;

	ll_node *to_node, *from_node;

	edge = elem;
	blk = edge->to;
	f = data;

	if (blk->visited == true) {
		return false;
	}

	to_node = blk->out.first;
	from_node = blk->in.first;

	fprintf(f, "Block #%u", edge->to->id);

	if (to_node) {
		fprintf(f, " links to");

		while(to_node) {
			edge = to_node->elem;
			fprintf(f, " #%u%s", edge->to->id, edge->dir == EDGE_NEXT ? "" : "(B)");

			to_node = to_node->next;
		}

	}

	if (from_node && ((block_edge *)from_node->elem)->type != EDGE_INIT) {
		fprintf(f, " reached from");

		while(from_node) {
			edge = from_node->elem;

			if (edge->from) {
				fprintf(f, " #%u%s", edge->from->id, edge->dir == EDGE_NEXT ? "" : "(B)");
			}

			from_node = from_node->next;
		}

	}

	fprintf(f, "\n");

	return true;
}

void block_graph_dump(function *functions, char *filename, char *mode) {
	function *func;
	FILE *f;

	if (!functions) {
		return;
	}

	if (!mode) {
		hinternal();
	}

	if (filename) {
		f = fopen(filename, mode);
	} else {
		f = stdout;
	}

	for (func = functions; func != NULL; func = func->next) {
		fprintf(f, "\nFunction %s:\n", func->name);

		graph_visit dump_visit = {
			.payload   = f,
			.policy    = VISIT_DEPTH,
			.dir       = VISIT_FORWARD,
			.pre_func  = block_graph_dump_pre,
			.post_func = NULL
		};

		block_graph_visit(func->source->in.first->elem, &dump_visit);
	}

	if (filename) {
		fclose(f);
	}
}

static void block_graph_visit_next(block_edge *edge, graph_visit *visit) {
	block *blk;
	block_edge *current;
	ll_node *tosched;

	if (visit->dir == VISIT_FORWARD) {
		blk = edge->to;
		tosched = blk->out.first;
	} else {
		blk = edge->from;
		tosched = blk->in.first;
	}

	if (visit->pre_func != NULL) {
		hnotice(6, "Pre-visiting block #%u\n", blk->id);

		if (visit->pre_func(edge, visit->payload) == false) {
			return;
		}
	}

	if (blk->visited == true) {
		return;
	} else {
		blk->visited = true;

		ll_push(&(visit->visited), blk);
	}

	while (tosched) {
		ll_push(&(visit->scheduled), tosched->elem);

		if (visit->policy == VISIT_DEPTH) {
			current = ll_pop(&(visit->scheduled));
		} else {
			current = ll_pop_first(&(visit->scheduled));
		}

		block_graph_visit_next(current, visit);

		tosched = tosched->next;
	}

	if (visit->post_func != NULL) {
		hnotice(6, "Post-visiting block #%u\n", blk->id);

		visit->post_func(edge, visit->payload);
	}
}

void block_graph_visit(block_edge *edge, graph_visit *visit) {
	block *blk;

	// A few sanity checks before running the visit
	if (edge == NULL) {
		hinternal();
	}
	else if (visit == NULL) {
		hinternal();
	}
	else if (visit->policy != VISIT_BREADTH && visit->policy != VISIT_DEPTH) {
		hinternal();
	}
	else if (visit->dir != VISIT_FORWARD && visit->dir != VISIT_BACKWARD) {
		hinternal();
	}
	else if (visit->pre_func == NULL && visit->post_func == NULL) {
		return;
	}

	// Visit initialization
	ll_init(&visit->scheduled);
	ll_init(&visit->visited);

	// Starting the visit
	block_graph_visit_next(edge, visit);

	// Clearing the effect of this visit not to hamper future ones
	while (!ll_empty(&(visit->visited))) {
		blk = ll_pop(&(visit->visited));

		blk->visited = false;
	}
}

static bool block_graph_complete_pre(void *elem, void *data) {
	block_edge *edge = elem;

	// If a node is already visited and part of the current path,
	// then we've identified a loop, therefore the nodes at the two
	// opposite ends of the current edge are respectively the loop
	// header and loop footer
	if (edge->to->visited == true && edge->to->active == true) {
		hnotice(4, "Block #%u tagged as loop header\n", edge->to->id);

		edge->dir = EDGE_BACK;
		edge->to->type = BLOCK_LOOP_HEADER;
		edge->from->type = BLOCK_LOOP_FOOTER;
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

static bool block_graph_complete_post(void *elem, void *data) {
	block_edge *edge = elem;

	// If we're leaving the current node, all paths in which it
	// participates have been visited, so we remove it from the current path
	edge->to->active = false;

	return true;
}

block *block_graph_create(void) {
	function *first, *func, *next, *prev, *callee;
	insn_info *instr;
	block *blocks, *current_blk, *new_blk, *temp_blk, *temp_new_blk;

	symbol *sym;

	hnotice(1, "Resolving CFG...\n");

	first = PROGRAM(v_code)[PROGRAM(version)];

	// The first block comprises the entire program, then it will be
	// progressively split until we obtain basic blocks
	current_blk = block_create();
	current_blk->begin = first->begin_insn;
	current_blk->end = find_last_insn(first);

	hnotice(4, "Program block #%u created from <%#08llx> to <%#08llx>\n",
		current_blk->id, current_blk->begin->orig_addr, current_blk->end->orig_addr);

	blocks = PROGRAM(blocks)[PROGRAM(version)] = current_blk;

	// For each instruction in each function, we begin iteratively
	// splitting current blocks into smaller and smaller chunks
	for (prev = NULL, func = first; func; prev = func, func = func->next) {

		hnotice(2, "Resolving CFG for function '%s' at <%#08llx>\n",
			func->name, func->begin_insn->orig_addr);

		// if (functions_overlap(prev, func)) {
		// 	// Handle the case of overlapping functions

		// 	func->begin_blk = prev->begin_blk;
		// 	func->end_blk = prev->end_blk;

		// 	func->source = prev->source;
		// 	func->calledfrom = prev->calledfrom;
		// 	func->callto = prev->callto;

		// 	continue;
		// }

		// Beginning of a function
		hnotice(3, "Function '%s' begin breakpoint at <%#08llx>\n",
			func->name, func->begin_insn->orig_addr);

		current_blk = block_split(current_blk, func->begin_insn, SPLIT_FIRST);
		func->begin_blk = current_blk;

		for (instr = func->begin_insn->next; instr->next; instr = instr->next) {

			// Beginning of function body
			if (instr->prev && !instr->prev->prev) {
				hnotice(3, "Function %s body breakpoint at <%#08llx>\n", func->name, instr->orig_addr);

				current_blk = block_split(current_blk, instr, SPLIT_LAST);

				block_link(func->begin_blk, current_blk, EDGE_FORCED);
			}

			// We've moved to a block which was already created during
			// a previous iteration
			if (instr->index > current_blk->end->index) {
				current_blk = current_blk->next;

				// Every instruction of the program must be mapped to its own block
				if (!current_blk) {
					hinternal();
				}
			}

			// Function exit point
			if (instr->next && IS_RET(instr->next)) {
				hnotice(3, "Function %s return breakpoint at <%#08llx>\n",
					func->name, instr->orig_addr);

				new_blk = block_split(current_blk, instr, SPLIT_FIRST);

				block_link(current_blk, new_blk, EDGE_FORCED);

				// if (instr->next && IS_RET(instr->next)) {
				// 	instr = instr->next;
				// }

				current_blk = new_blk;
			}

			// Other special cases
			if (IS_JUMPIND(instr)) {
				unsigned long idx;
				insn_info *target;

				hnotice(3, "Indirect jump breakpoint at <%#08llx>\n", instr->orig_addr);

				new_blk = block_split(current_blk, instr, SPLIT_LAST);

				idx = 0;
				while (idx < instr->jumptable.size) {
					target = instr->jumptable.entry[idx];

					hnotice(3, "Jump target breakpoint (jumptable) at <%#08llx>\n", target->orig_addr);

					temp_blk = block_find(target);

					if (!temp_blk) {
						hinternal();
					}

					temp_new_blk = block_split(temp_blk, target, SPLIT_FIRST);

					// If the instruction *before* the target one is not a jump,
					// then it is a labeled instruction and there's no flow control
					// hijacking between the two resulting blocks
					// For this reason, they must be explicitly connected
					if (!IS_JUMP(target->prev)) {
						block_link(temp_blk, temp_new_blk, EDGE_FORCED);
					}

					// The current block gets linked with the block whose first
					// instruction is the target of the jump
					block_link(current_blk, temp_new_blk, EDGE_IND);

					idx = idx + 1;
				}

				current_blk = new_blk;
			}

			else if (IS_JUMP(instr)) {
				hnotice(3, "Jump instruction %s breakpoint at <%#08llx> to target <%#08llx>\n",
					(IS_CONDITIONAL(instr) ? "(conditional)" : "(absolute)"),
					instr->orig_addr, instr->jumpto->orig_addr);

				new_blk = block_split(current_blk, instr, SPLIT_LAST);

				// The target of a jump creates a link between blocks, but we keep
				// splitting blocks in an ordered manner: from first to last instruction
				hnotice(3, "Jump target breakpoint at <%#08llx>\n", instr->jumpto->orig_addr);

				temp_blk = block_find(instr->jumpto);

				if (!temp_blk) {
					hinternal();
				}

				temp_new_blk = block_split(temp_blk, instr->jumpto, SPLIT_FIRST);

				// If the instruction *before* the target one is not a jump,
				// then it is a labeled instruction and there's no flow control
				// hijacking between the two resulting blocks
				// For this reason, they must be explicitly connected
				if (!IS_JUMP(instr->jumpto->prev)) {
					block_link(temp_blk, temp_new_blk, EDGE_FORCED);
				}

				// The current block gets linked with the block whose first
				// instruction is the target of the jump
				block_link(current_blk, temp_new_blk,
					IS_CONDITIONAL(instr) ? EDGE_THEN : EDGE_GOTO);

				// Conditional jumps can branch into the new block, therefore
				// in that case we need to connect the old block with the new
				if (IS_CONDITIONAL(instr)) {
					block_link(current_blk, new_blk, EDGE_ELSE);
				}

				current_blk = new_blk;
			}

			else if (IS_CALLIND(instr)) {
				unsigned long idx;
				insn_info *target;

				hnotice(3, "Indirect call breakpoint at <%#08llx>\n", instr->orig_addr);

				new_blk = block_split(current_blk, instr, SPLIT_LAST);

				block_link(current_blk, new_blk, EDGE_CALLRET);

				// Single function pointer
				if (instr->jumpto) {
					callee = find_func_from_instr(instr->jumpto, NEW_ADDR);

					if (callee) {
						hnotice(3, "Discovered call from block #%u to function '%s'\n",
							current_blk->id, callee->name);
						current_blk->callto = callee;

						// TODO: Da evitare di inserire se era già presente
						ll_push(&callee->calledfrom, current_blk);
						ll_push(&func->callto, callee);
					}
				}

				// Array of function pointers
				else {
					current_blk->calltable.size = instr->jumptable.size;
					current_blk->calltable.entry = malloc(sizeof(function *) * instr->jumptable.size);

					idx = 0;
					while (idx < instr->jumptable.size) {
						target = instr->jumptable.entry[idx];

						hnotice(3, "Call target breakpoint (calltable) at <%#08llx>\n", target->orig_addr);

						callee = find_func_from_instr(target, NEW_ADDR);

						if (callee) {
							hnotice(3, "Discovered call from block #%u to function '%s'\n",
								current_blk->id, callee->name);
							current_blk->calltable.entry[idx] = callee;

							// TODO: Da evitare di inserire se era già presente
							ll_push(&callee->calledfrom, current_blk);
							ll_push(&func->callto, callee);
						}

						idx = idx + 1;
					}

				}

				current_blk = new_blk;
			}

			else if (IS_CALL(instr)) {
				sym = instr_reference_weak(instr);

				if (sym == NULL) {
					hinternal();
				}

				hnotice(3, "Call instruction breakpoint at <%#08llx> to function %s\n",
					instr->orig_addr, sym->name);

				new_blk = block_split(current_blk, instr, SPLIT_LAST);

				block_link(current_blk, new_blk, EDGE_CALLRET);

				// We skip function declarations that don't have an actual
				// definition in our relocatable object
				if (instr->jumpto) {
					callee = find_func_from_instr(instr->jumpto, NEW_ADDR);

					if (callee) {
						hnotice(3, "Discovered call from block #%u to function '%s'\n",
							current_blk->id, callee->name);
						current_blk->callto = callee;

						// TODO: Da evitare di inserire se era già presente
						ll_push(&callee->calledfrom, current_blk);
						ll_push(&func->callto, callee);
					}
				}

				current_blk = new_blk;
			}

		}

		// End of function
		hnotice(3, "Function %s end breakpoint at <%#08llx>\n",
			func->name, instr->orig_addr);

		func->end_blk = current_blk;

		// Hackish way to make the splitting work as expected: we fast-forward
		// the function chain until we skip over all aliases for the current
		// function... the first non-overlapping function is temporarily
		// linked with the current one in terms of instructions
		// TODO: Find a better way
		// for (next = func->next; next; next = next->next) {
		// 	if (!functions_overlap(func, next)) {
		// 		break;
		// 	}
		// }
		next = func->next;

		if (next) {
			instr->next = next->begin_insn;
		}

		current_blk = block_split(current_blk, instr, SPLIT_LAST);

		// Restoring end of function...
		instr->next = NULL;

		// Now let's compute block lengths, as well as the source block
		for (current_blk = func->begin_blk; current_blk != func->end_blk->next; current_blk = current_blk->next) {

			if (ll_empty(&current_blk->in)) {
				block_edge *edge;

				edge = malloc(sizeof(block_edge));
				edge->type = EDGE_INIT;
				edge->dir = EDGE_NEXT;
				edge->from = NULL;
				edge->to = current_blk;

				ll_push(&(current_blk->in), edge);

				func->source = current_blk;
			}

			instr = current_blk->begin;

			while (instr != current_blk->end->next) {
				current_blk->length += 1;

				instr = instr->next;
			}

			// hnotice(4, "Block #%u has length %u\n", current_blk->id, current_blk->length);
		}

		// Let's complete the graph by inferring program loops
		graph_visit loop_visit = {
			.payload   = NULL,
			.policy    = VISIT_DEPTH,
			.dir       = VISIT_FORWARD,
			.pre_func  = block_graph_complete_pre,
			.post_func = block_graph_complete_post
		};

		block_graph_visit(func->source->in.first->elem, &loop_visit);
	}

	if (config.verbose > 6) {
		block_tree_dump("treedump.txt", "a+");
		block_graph_dump(PROGRAM(v_code)[PROGRAM(version)], "graphdump.txt", "a+");
	}

	return blocks;
}
