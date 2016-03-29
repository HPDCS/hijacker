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
* @file instruction.c
* @brief Module to handle instructions in the IBR
* @author Simone Economo
*/

#include <stdlib.h>
#include <string.h>
#include <strings.h>

#include <hijacker.h>
#include <prints.h>
#include <ibr.h>
#include <instruction.h>

#include <x86/x86.h>
#include <elf/handle-elf.h>


#define MAX_LOOKBEHIND		10 // [SE] Used while reverse-parsing instruction to resolve jump tables


/**
 * Fills up instruction meta-data (both architecture-independent
 * and architecture-specific) according to the instruction mnemonic
 * string and the target ISA. Notice that the instruction descriptor
 * must be already allocated by the caller function, hence a side-
 * effect is performed on it.
 *
 * @param  instr    Pointer to the instruction descriptor to fill.
 * @param  isa      Target architecture.
 * @param  mnemonic Textual representation of the instruction.
 *
 * @return          The number of characters that are effectively
 *                  consumed from the beginning of the string, or 0
 *                  if the string is not valid in the target ISA.
 */
static size_t instr_assemble(isn_t *instr, isa_family_t isa,
                             const char *mnemonic) {
	// TODO: To implement
	return 42; // The best integer placeholder ever!
}


/**
 * Fills up instruction meta-data (both architecture-independent
 * and architecture-specific) according to the instruction's raw
 * bytes and the target ISA. Notice that the instruction descriptor
 * must be already allocated by the caller function, hence a side-
 * effect is performed on it.
 *
 * Observe that this function doesn't require to specify a length
 * for the raw bytes sequence. In fact, it is able to determine
 * the length of the instruction to disassemble provided that a
 * disassembly engine is available for the target architecture.
 * The number of bytes effectively consumed by the engine is
 * provided as output. This is especially useful when the target
 * ISA represents a CISC architecture.
 *
 * @param  instr Pointer to the instruction descriptor to fill.
 * @param  isa   Target architecture.
 * @param  bytes Raw bytes of the instruction.
 *
 * @return       The number of bytes that are effectively consumed
 *               from the beginning of the bytes sequence, or 0 if
 *               the sequence is not valid in the target ISA.
 */
static size_t instr_disassemble(isn_t *instr, isa_family_t isa,
                                const unsigned char *bytes) {
	// TODO: To implement
	return 42; // The best integer placeholder ever!
}

/**
 * Inserts one or more instructions into the instruction chain,
 * relative to the position of another already-existing instruction,
 * and returns a range of newly-inserted instruction descriptors.
 *
 * Observe that this function allocates new instruction descriptors
 * in dynamic memory.
 *
 * @param  input Pointer to the input representation of the
 *               instruction.
 * @param  type  Type of the input representation (i.e., mnemonic
 *               string or raw byte sequence).
 * @param  pivot Pointer to the instruction descriptor used as
 *               reference for the insertion. If NULL, it is
 *               inserted at the beginning of at the end of
 *               the chain, depending on the value of `mode`.
 * @param  mode  Where the instructions will be inserted, relative
 *               to the pivot (i.e., before or after the pivot).
 *
 * @return       Inclusive range of newly-inserted instruction
 *               descriptors; if the input representation is an
 *               empty sequence, the range is NULL-delimited on
 *               both sides.
 */
list_range_t instr_insert(const unsigned char *input, isn_input_type type,
                          isn_t *pivot, list_insert_mode mode) {
	isn_t *instr, *prev, *newpivot, *first, *last;

	if (!input) {
		hinternal();
	}

	// TODO: Update instruction addresses: since we are adding
	// new instructions, the shift amount is equal to their size
	// TODO: Update parent function symbol size
	// TODO: Update virtual reference

	// If we wish to insert before the pivot, the first instruction
	// is inserted backwards and the remaining instructions forwards.
	// If we want to insert after, we simply decouple the first
	// forward insertion from the other ones.
	// This is done to simplify the remaining logic of this function.
	newpivot = instr_insert_single(&input, type, pivot, mode);

	// Insert the remaining instructions into the chain (notice that
	// the `INSERT_AFTER` policy can be enforced at this point)
	prev = NULL;
	instr = newpivot;

	while (instr) {
		prev = instr;
		instr = instr_insert_single(&input, type, instr, INSERT_AFTER);
	}

	// By now, `prev` points to the latest inserted instruction, or
	// it is NULL if the first insertion has failed
	if (mode == INSERT_AFTER) {
		newpivot = prev;
	}

	if (!newpivot) {
		return range(NULL, NULL);
	}

	if (mode == INSERT_AFTER) {
		first = pivot->node->next;
		last = newpivot->node;
	} else {
		first = newpivot->node;
		last = pivot->node->prev;
	}

	return range(first, last);
}


/**
 * Inserts a single instruction into the instruction chain relative
 * to the position of another, already-existing instruction.
 *
 * Observe that this function performs a single insertion at a
 * time, one per each invocation. It is used as a building block
 * for its public counterpart, `instr_insert`, which allows to
 * insert many instructions at once in the chain.
 *
 * To simplify the logic of `instr_insert`, this function performs
 * a side-effect on its first argument. Specifically, the pointer
 * to the input representation will advance by a number of bytes
 * which is equivalent to those that were consumed in the latest
 * invocation. As a result, upon multiple calls to this function,
 * the first argument will always point to the next instruction
 * to parse, or to the end of the sequence if there is no other
 * instruction to insert.
 *
 * @param  input Double pointer to the input representation of
 *               the instruction.
 * @param  type  Type of the input representation (i.e., mnemonic
 *               string or raw byte sequence).
 * @param  pivot Pointer to the instruction descriptor used as
 *               reference for the insertion. If NULL, it is
 *               inserted at the beginning of at the end of
 *               the chain, depending on the value of `mode`.
 * @param  mode  Where the instruction will be inserted, relative
 *               to the pivot (i.e., before or after the pivot).
 *
 * @return       Pointer to the newly-inserted instruction, or
 *               NULL if the input representation is an empty
 *               sequence of instructions.
 */
static isn_t *instr_insert_single(const unsigned char **input, isn_input_type type,
                                  isn_t *pivot, list_insert_mode mode) {
	isn_t *instr;

	size_t consumed;

	// Make room for a new instruction descriptor
	instr = hcalloc(sizeof(isn_t));

	// Fill up the instruction descriptor in the appropriate manner
	if (type == INSTR_MNEMONIC) {
		consumed = instr_assemble(instr,
			config.program.arch, (const char *) *input);
	}
	else if (type == INSTR_RAWBYTES) {
		consumed = instr_disassemble(instr,
			config.program.arch, *input);
	}

	if (consumed == 0) {
		free(instr);
		return NULL;
	}

	// Update the input pointer according to the consumed bytes
	*input += consumed;

	// Insert the descriptor into the instruction chain
	instr->node = list_insert(&__VERSION__(instructions), instr, pivot->node, mode);

	// TODO: Handle the case of block boundaries
	// 1. Find pivot's block
	// 2. If jump or call, split at it
	// 3. Merge to current block otherwise

	return instr;
}


/**
 * Removes a range of instruction descriptors from the chain.
 *
 * It can be used to remove a single instruction, provided that
 * range delimiters point to the same instruction descriptor.
 *
 * Observe that this function deallocates the passed instruction
 * descriptors, therefore they will be no longer valid upon
 * returning from this function.
 *
 * @param instructions Range of instruction descriptors to remove.
 */
void instr_remove(list_range_t instructions) {
	isn_t *instr;

	if (instructions.first == NULL || instructions.last == NULL) {
		hinternal();
	}

	// TODO: Check that `last` comes after `first`
	// TODO: What to do with other ranges pointing to removed
	// instructions?
	// TODO: Update instruction addresses: since we are removing
	// instructions, the shift amount is equal to their size * -1
	// TODO: Update parent function symbol size

	// At each invocation of the list range removal function,
	// the next instruction to remove is returned
	do {
		instr = list_remove_range(&__VERSION__(instructions), instructions);

		// If no more elements are left in the range, just return
		if (!instr) {
			return;
		}

		// Otherwise, we can remove the instruction descriptor which
		// was held by the removed list node
		instr_remove_single(instr);
	} while(true);
}


/**
 * Removes a single instruction from the instruction chain.
 *
 * Observe that this function is used as a building block for its
 * public counterpart, `instr_remove`, which allows to remove many
 * instructions at once from the chain.
 *
 * @param instr Pointer to the instruction descriptor to remove.
 */
static void instr_remove_single(isn_t *instr) {

	// TODO: Handle the case of block boundaries
	// TODO: Remove all relocations referring to this instruction

	// Deallocate the descriptor, which is no longer valid
	free(instr);
}


/**
 * Replaces one or more existing instructions in the chain with
 * one or more instructions.
 *
 * Observe that this function removes the passed range of
 * instructions even if there's no replacement.
 *
 * @param  input        Pointer to the input representation of the
 *                      instruction.
 * @param  type         Type of the input representation (i.e., mnemonic
 *                      string or raw byte sequence).
 * @param  instructions Range of instruction descriptors to remove.
 *
 * @return              Inclusive range of newly-inserted instruction
 *                      descriptors; if the input representation is an
 *                      empty sequence, the range is NULL-delimited on
 *                      both sides.
 */
list_range_t instr_replace(const unsigned char *input, isn_input_type type,
                           list_range_t instructions) {
	list_range_t range;

	if (!range_valid(instructions)) {
		hinternal();
	}

	// This is as simple as performing an insertion and then
	// a removal
	range = instr_insert(input, type, instructions.first, INSERT_BEFORE);
	instr_remove(instructions);

	// It can be NULL if we tried to insert an empty sequence of
	// instructions, but this doesn't influence removal
	return range;
}


isn_t *instr_find_byaddr(addr_t address, fun_t *function) {
	list_node_t *node;
	blk_t *block, *prev;
	isn_t *instr;

	if (!function) {
		hinternal();
	}

	list_for_each(&function->blocks, node) {
		block = node->elem;

		if (block_first_instr(block)->offset > address) {
			break;
		}

		prev = block;
	}

	list_for_each(&block->instructions, node) {
		instr = node->elem;

		if (instr->offset <= address
		    && instr->offset + instr->length > address) {
			return instr;
		}
	}

	return NULL;
}


/**
 * Given a symbol, this function will create a new CALL instruction and returns it.
 * The instruction can be passed to the insertion function to add it to the
 * remainder of the code.
 *
 * @param target Pointer to the pivot instruction descriptor.
 * @param function Name of the function to be called.
 * @param mode Integer constant representing whether the instruction is inserted
 * before, after or in place of the target one.
 * @param instr Pointer to the CALL instruction just created.
 */
void add_call_instruction(insn_info *target, unsigned char *name, insn_insert_mode mode, insn_info **instr) {
	section *sec;
	symbol *sym;

	unsigned char call[5];

	bzero(call, sizeof(call));
	switch (PROGRAM(insn_set)) {
		case X86_INSN:
			call[0] = 0xe8;
		break;
	}

	for (sec = PROGRAM(sections)[PROGRAM(version)]; sec; sec = sec->next) {
		if (sec->type == SECTION_CODE) {
			break;
		}
	}

	if (sec == NULL) {
		hinternal();
	}

	// Creates the symbol name
	sym = symbol_create(name, SYMBOL_UNDEF, SYMBOL_GLOBAL, sec, 0);

	// Adds the instruction to the binary representation
	// WRANING! We MUST add the instruction BEFORE creating
	// the new rela node, otherwise the instruction's address
	// will not be coherent anymore once at the amitting step
	insert_instructions_at(target, call, sizeof(call), mode, instr);

	// Once the instruction has been inserted into the binary representation
	// and each address and reference have been properly updated,
	// create a new RELA entry
	symbol_instr_rela_create(sym, *instr, RELOC_PCREL_32);
}


void add_jump_instruction(insn_info *target, unsigned char *name, insn_insert_mode mode, insn_info **instr) {
	section *sec;
	symbol *sym;

	unsigned char jump[5];

	bzero(jump, sizeof(jump));
	switch (PROGRAM(insn_set)) {
		case X86_INSN:
			jump[0] = 0xe9;
		break;
	}

	for (sec = PROGRAM(sections)[PROGRAM(version)]; sec; sec = sec->next) {
		if (sec->type == SECTION_CODE) {
			break;
		}
	}

	if (sec == NULL) {
		hinternal();
	}

	// Creates the symbol name
	sym = symbol_create(name, SYMBOL_UNDEF, SYMBOL_GLOBAL, sec, 0);

	// Adds the instruction to the binary representation
	// WRANING! We MUST add the instruction BEFORE creating
	// the new rela node, otherwise the instruction's address
	// will not be coherent anymore once at the amitting step
	insert_instructions_at(target, jump, sizeof(jump), mode, instr);
	//insert_insn_at(target, instr, where);

	// Once the instruction has been inserted into the binary representation
	// and each address and reference have been properly updated,
	// create a new RELA entry
	symbol_instr_rela_create(sym, *instr, RELOC_PCREL_32);
}


/**
 * Sets the target of a JUMP/CALL instruction in the intermediate representation.
 *
 * @param jump Pointer to the JUMP/CALL instruction descriptor.
 * @param target Pointer to the target instruction descriptor.
 *
 * @author Simone Economo
 */
inline void set_jumpto_reference(insn_info *jump, insn_info *target) {
	jump->jumpto = target;

	ll_push(&target->targetof, jump);

	hnotice(3, "%s instruction at <%#08llx> (<%#08llx>) linked to instruction <%#08llx> at address <%#08llx> (<%#08llx>)\n",
		IS_JUMP(jump) ? "Jump" : "Call",
		jump->orig_addr, jump->new_addr, (unsigned long long) target, target->orig_addr, target->new_addr);
}

/**
 * Sets a single entry of the jumptable associated with an indirect JUMP/CALL
 * instruction in the intermediate representation.
 *
 * @param jump Pointer to the indirect JUMP/CALL instruction descriptor.
 * @param entry Pointer to the target instruction descriptor.
 * @param idx Index of the entry that gets overwritten in the jumptable.
 *
 * @author Simone Economo
 */
inline void set_jumptable_entry(insn_info *jump, insn_info *entry, unsigned int idx) {
	if (idx >= jump->jumptable.size) {
		hinternal();
	}

	jump->jumptable.entry[idx] = entry;

	hnotice(3, "%s instruction at <%#08llx> (<%#08llx>) linked to instruction <%#08llx> at address <%#08llx> (<%#08llx>) in entry %u\n",
		IS_JUMP(jump) ? "Jump" : "Call",
		jump->orig_addr, jump->new_addr, (unsigned long long) entry, entry->orig_addr, entry->new_addr, idx);
}


/**
 * Sets the virtual reference of any instruction which is the target of another
 * (indirect) JUMP/CALL instruction. More precisely, a virtual instruction is
 * used (and useful) when the another instruction is subject to multiple
 * instrumentation rules whose preambles are inserted one below another.
 * After calling this function, any instruction that pointed to the original
 * target will now point to the virtual reference instead.
 *
 * @param target Pointer to the target instruction descriptor.
 * @param virtual Pointer to the virtual instruction descriptor.
 *
 * @author Simone Economo
 */
void set_virtual_reference(insn_info *target, insn_info *virtual) {
	insn_info *jump;

	unsigned int idx;

	while( !ll_empty(&target->targetof) ) {
		jump = ll_pop_first(&target->targetof);

		ll_push(&virtual->targetof, jump);

		if (jump->jumpto) {
			// if (jump->jumpto == target) {
				jump->jumpto = virtual;

				hnotice(3, "%s instruction at <%#08llx> (<%#08llx>) linked to virtual instruction at address <%#08llx> (<%#08llx>)\n",
					IS_JUMP(jump) ? "Jump" : "Call",
					jump->orig_addr, jump->new_addr, virtual->orig_addr, virtual->new_addr);
			// }
		}
		else {
			for(idx = 0; idx < jump->jumptable.size; ++idx) {
				if (jump->jumptable.entry[idx] == target) {
					jump->jumptable.entry[idx] = virtual;

					hnotice(4, "%s instruction at <%#08llx> (<%#08llx>) linked to virtual instruction at address <%#08llx> (<%#08llx>) in entry %u\n",
						IS_JUMP(jump) ? "Jump" : "Call",
						jump->orig_addr, jump->new_addr, virtual->orig_addr, virtual->new_addr, idx);
				}
			}
		}

	}

	target->virtual = virtual;

	if (target->pointedby) {
		virtual->pointedby = target->reference;
		virtual->pointedby->relocation.target_insn = virtual;

		target->pointedby = NULL;

		// virtual->reference->relocation.offset = virtual->new_addr;
	}
}


static void set_jump_table(function *func, insn_info *instr, section *sec,
	unsigned long long addr, unsigned long long size) {

	section *text;
	insn_info *target;
	symbol *rel;
	function *callee;

	unsigned int i;

	text = func->symbol->sec;

	// Find the relocation entry associated with the table base address
	linked_list relocs = { NULL, NULL };
	ll_node *relnode;
	rel = NULL;

	find_relocations(PROGRAM(symbols), sec, text->sym, &relocs);

	for (relnode = relocs.first; relnode; relnode = relnode->next) {
		rel = relnode->elem;

		if (rel->relocation.offset == addr) {
			break;
		}
	}

	if (rel == NULL) {
		hinternal();
	}

	// Make room for the new jump table
	instr->jumptable.size = size;
	instr->jumptable.entry = malloc(sizeof(insn_info *) * size);

	// Keep parsing relocation entries until we reach the
	// boundary of the jump table
	i = 0;

	while(i < size && relnode) {
		rel = relnode->elem;

		if (IS_JUMPIND(instr)) {
			target = find_insn(func, rel->relocation.addend, true);

			set_jumptable_entry(instr, target, i);
		}

		else if (IS_CALLIND(instr)) {
			callee = rel->func;

			if (rel->relocation.addend) {
				// It doesn't make much sense to compute the address of a function
				// from the address of another function and a displacement, but we
				// handle that possibility anyway...
				// [SE] TODO: Questo branch è abbastanza inutile
				target = find_insn(NULL, callee->begin_insn->orig_addr + rel->relocation.addend, true);

				if (!target) {
					hinternal();
				}
			} else {
				target = callee->begin_insn;
			}

			set_jumptable_entry(instr, target, i);
		}

		else {
			hinternal();
		}

		i = i + 1;
		relnode = relnode->next;
	}
}


static void resolve_jump_table(function *func, insn_info *instr) {
	insn_info *backinstr;
	symbol *sym;
	section *sec;
	function *callee;

	unsigned long start;
	unsigned long size;
	unsigned int i;

	backinstr = instr;
	sym = sec = callee = NULL;
	start = size = 0;


	// Code for indirect jumps (very very unreliable!)
	if (IS_JUMPIND(instr)) {
		bool start_found;
		bool size_found;

		start_found = size_found = false;

		// We keep searching for the start address and the size of the jump table
		backinstr = instr;
		i = 0;

		while(backinstr && i < MAX_LOOKBEHIND && (!start_found || !size_found)) {

			if (!start_found && IS_MEMRD(backinstr)) {
				sym = backinstr->reference;

				// We make the reasonable assumption that case statement addresses are in .rodata
				if (sym && str_equal(sym->name, ".rodata")) {
					sec = sym->sec;
					start = sym->relocation.addend;

					start_found = true;
				}
			}

			else if (!size_found && IS_CTRL(backinstr)) {
				switch(PROGRAM(insn_set)) {
					case X86_INSN:
						// [SE] TODO: Bisognerebbe beccare non semplicemente una CMP, ma quella
						// che ha come destinazione il registro utilizzato nella MOV precedente,
						// cioè quello impiegato come valore di indice per la jump table
						size = backinstr->i.x86.immed;
						break;

					default:
						size = 0;
				}

				size_found = true;
			}

			backinstr = backinstr->prev;
			i = i + 1;
		}

		// It doesn't make sense to have zero-sized jump tables, therefore
		// we assume that this check is safe enough...
		if (size > 0) {
			hnotice(6, "JT starting at %s + <%#08llx> and sized %lu\n",
				sec->name, (unsigned long long) start, size);

			// The immediate value of the previous CMP instruction is inclusive of
			// the last case statement, hence it must be increased by one if we
			// wish to use it as the size of the jump table
			size = size + 1;
			set_jump_table(func, instr, sec, start, size);
		}
	}


	// Code for indirect calls (slightly more reliable)
	else if (IS_CALLIND(instr)) {
		backinstr = instr->prev;
		i = 0;

		while(backinstr && i < MAX_LOOKBEHIND) {

			if (IS_MEMRD(backinstr) || IS_MEMWR(backinstr)) {
				sym = backinstr->reference;

				if (sym != NULL) {
					// Single function pointer
					if (sym->type == SYMBOL_FUNCTION) {
						callee = sym->func;
					}
					// Array of function pointers
					else if (sym->type == SYMBOL_VARIABLE) {
						sec = sym->sec;
						start = sym->offset;
						size = sym->size / sizeof(char *);
					}
					else {
						backinstr = backinstr->prev;
						i = i + 1;
						continue;
					}

					break;
				}
			}

			backinstr = backinstr->prev;
			i = i + 1;
		}

		// Zero-sized call tables mean a single function pointer
		if (callee && size == 0) {
			hnotice(6, "Function pointer to %s\n", callee->name);

			set_jumpto_reference(instr, callee->begin_insn);
		}

		else if (size) {
			hnotice(6, "Array named %s starting at %s + <%#08llx> and sized %lu\n",
				sym->name, sec->name, (unsigned long long) start, size);

			set_jump_table(NULL, instr, sec, start, size);
		}
	}


	// Cannot handle any other kind of instruction
	else {
		hinternal();
	}
}


/**
 * Links jumps instructions to destination ones.
 * Provided a valid function's descriptors, it will look up for all the jump instructions
 * and will link them to their relative destination ones.
 *
 * @param func The pointer to a valid function's descriptors
 */

void link_jump_instructions(function *func) {
	insn_info *instr;
	insn_info *dest;

	function *callee;
	symbol *sym;

	unsigned long long jmp_addr;

	hnotice(2, "Resolve jumps/calls of function '%s'\n", func->name);

	// For each instruction, look for jump/call ones
	for (instr = func->begin_insn; instr; instr = instr->next) {

		if(IS_JUMP(instr)) {
			// If the jump instruction has a reference, this means that a relocation
			// has to be applied. Hence, looking for the target instruction is incorrect.
			if (instr->reference != NULL) {
				// Simply skip the instruction; the linker will be in charge to correctly handle it
				continue;
			}

			else if (IS_JUMPIND(instr)) {
				// [SE] If the instruction is an indirect jump, try to resolve its
				// associated jump table (currently only for switch-case statements)
				// NOTE: This is a very naive and loose algorithm that may fail
				// in several cases, and is not kitten-proof! Beware!

				resolve_jump_table(func, instr);
			}

			else {

				switch(PROGRAM(insn_set)) {
					case X86_INSN:
						jmp_addr = instr->orig_addr + instr->i.x86.insn_size + instr->i.x86.jump_dest;
						break;

					default:
						hinternal();
				}

				dest = find_insn_cool(func->begin_insn, jmp_addr);

				if(!dest) {
					hinternal();
				}

				// At this point 'dest' will point to the destination instruction
				// relative to the jump 'instr'
				set_jumpto_reference(instr, dest);
			}

		}


		else if(IS_CALL(instr)) {

			if (IS_CALLIND(instr)) {
				// [SE] Handle indirect calls (tricky, uses the same naive algorithm
				// as for switch-case statements)
				resolve_jump_table(func, instr);
			}

			else {
				// A CALL could be seen as a JUMP and could help in handling the
				// embedded offset to local functions

				switch(PROGRAM(insn_set)) {
					case X86_INSN:
						jmp_addr = instr->i.x86.jump_dest;
						break;

					default:
						hinternal();
				}

				if (jmp_addr != 0) {
					// If the CALL has a non-null embedded offset, it is a call to a local function and
					// the format is the same as a jump. The offset is interpreted, the called function
					// retrieved and the instruction is translated into a zero'd CALL with an associated
					// relocation entry.

					// NOTE: credo che fosse scorretto nel caso delle funzioni locali, infatti
					// non trovava la funzione
					jmp_addr += instr->orig_addr + instr->size;

					hnotice(4, "Call to a local function at <%#08llx> detected\n", jmp_addr);

					callee = find_func_from_addr(jmp_addr);

					if (!callee) {
						hinternal();
					}

					// CALL instruction embedded offset must be reinitialized to zero
					switch(PROGRAM(insn_set)) {
						case X86_INSN:
							memset(instr->i.x86.insn + 1, 0, (instr->size - instr->opcode_size));
							break;
					}

				}

				else {
					// [SE] If the CALL instruction has no embedded offset, it is already
					// associated with a relocation. In this case, we must check whether
					// is it a CALL to a local function or not, and act accordingly.

					// jmp_addr = instr->reference->position;

					// It means the function is defined elsewhere (i.e. in a different file object)
					// meaning that the linker will be in charge to correctly handle it
					if (instr->reference->size == 0) {
						// instr = instr->next;
						continue;
					}

					// callee = find_func_from_addr(jmp_addr);
					callee = instr->reference->func;

					if (!callee) {
						hinternal();
					}
				}

				// if (callee) {
					// CALL to local function detected, augment the intermediate representation
					// with the appropriate linking between instructions.
					hnotice(4, "Callee function '%s' at <%#08llx> found\n", callee->name, callee->orig_addr);

					// At this point 'callee' will point to the destination function
					// relative to the call; the only thing we have to do is to add the
					// reference to the relative function's symbol so that, in the future
					// emit step, the code will automatically retrieve the correct final
					// address of the relocation. In such a way we threat local function
					// calls as relocation entities.
					sym = callee->symbol;

					if (instr->reference == NULL || PROGRAM(version) > 0) {
						// The instruction object will be bound to the proper symbol
						symbol_instr_rela_create(sym, instr, RELOC_PCREL_32);
					}

					set_jumpto_reference(instr, callee->begin_insn);
				// }

			}

		}

	}

}


/**
 * Updates all the instruction addresses, starting from the beginning of the
 * program all the way to its end. An offset variable takes into account the
 * sizes of each instruction already met, and incrementally determines the final
 * address of the next instruction. Notice that the function only updates the
 * new address, leaving the original address untouched for debugging purposes.
 *
 * @author Davide Cingolani
 */
void update_instruction_addresses(int version) {
	function *foo;
	insn_info *instr;

	unsigned long long offset;
	unsigned long long old_offset;
	unsigned long long foo_size;

	long long rela_offset;

	hnotice(4, "Recalculate instructions' addresses\n");

	// Instruction addresses are recomputed from scratch starting from the very beginning
	// of the code section.
	foo = PROGRAM(v_code)[version];
	offset = 0;
	while(foo) {

		hnotice(5, "Updating instructions in function '%s'\n", foo->name);

		foo_size = 0;

		instr = foo->begin_insn;
		while(instr != NULL) {

			old_offset = instr->new_addr;
			// instr->i.x86.addr = instr->new_addr = offset;
			instr->new_addr = offset;

			offset += instr->size;
			foo_size += instr->size;

			// [SE] Updates the relocation entry to reflect the address update
			// if (instr->reference) {
			// 	instr->reference->relocation.offset = instr->new_addr + rela_offset;
			// }
			if (instr->reference) {
				// rela_offset = instr->reference->relocation.offset - instr->new_addr;
				instr->reference->relocation.offset = instr->new_addr + instr->opcode_size;
			}
			// [SE] TODO: Hackish way to check for relocation from .text to .rodata, find better one
			if (instr->pointedby && !strncmp((const char *)instr->pointedby->name, ".text", 5)) {
				instr->pointedby->relocation.addend = instr->new_addr;
			}
			// [/SE]

			hnotice(6, "Instruction '%s' <%#08llx> at old address <%#08llx> (size %u) has new address <%#08llx>\n",
				instr->i.x86.mnemonic, (unsigned long long) instr, old_offset, instr->size, instr->new_addr);

			instr = instr->next;
		}

		foo->symbol->size = foo_size;

		hnotice(4, "Function '%s' updated to <%#08llx> (%d bytes)\n",
			foo->symbol->name, foo->begin_insn->new_addr, foo->symbol->size);

		foo = foo->next;
	}

}

static void set_jump_displacement(insn_info *jump, insn_info *target) {
	long displacement;

	unsigned int offset;
	unsigned int size;

	insn_info_x86 *x86;

	if (!jump || !target) {
		hinternal();
	}

	if (IS_CALL(jump))
		return;

	switch(PROGRAM(insn_set)) {
	case X86_INSN:

		x86 = &(jump->i.x86);
		offset = x86->opcode_size;
		size = x86->insn_size - x86->opcode_size - x86->disp_size;

		displacement = target->new_addr - (jump->new_addr + jump->size);

		memcpy((x86->insn + offset), &displacement, size);
		break;

	default:
		hinternal();
	}

	hnotice(4, "%s instruction at <%#08llx> (<%#08llx>) has updated displacement %#0llx\n",
		IS_JUMP(jump) ? "Jump" : "Call",
		jump->orig_addr, jump->new_addr, (unsigned long long) displacement);
}


void set_call_displacement(insn_info *jump, insn_info *target) {
	long displacement;

	unsigned int offset;
	unsigned int size;

	insn_info_x86 *x86;

	if (!jump || !target) {
		hinternal();
	}

	switch(PROGRAM(insn_set)) {
	case X86_INSN:

		x86 = &(jump->i.x86);
		offset = x86->opcode_size;
		size = x86->insn_size - x86->opcode_size - x86->disp_size;

		displacement = target->new_addr - (jump->new_addr + jump->size);

		memcpy((x86->insn + offset), &displacement, size);
		break;

	default:
		hinternal();
	}

	hnotice(4, "Call instruction at <%#08llx> (<%#08llx>) has updated displacement %#0llx\n",
		jump->orig_addr, jump->new_addr, (unsigned long long) displacement);
}

/**
 * Starting from the target instruction, the function will perform an update
 * of all the addresses of the instructions that follow.
 *
 * @param target Pointer to the target instruction descriptor, starting from
 * which shifting is performed.
 * @param shift (Signed) number of bytes by which to shift all the addresses.
 *
 * @author Davide Cingolani
 * @author Simone Economo
 */
static void shift_instruction_addresses(insn_info *target, int shift) {
	function *foo, *prev;
	insn_info *instr;

	ll_node *jump_node;
	insn_info *jump;

	foo = PROGRAM(code);
	prev = NULL;
	instr = NULL;

	hnotice(4, "Shifting the addresses of instructions beyond <%#08llx> by %+d bytes\n",
		target->new_addr, shift);

	// Skip functions that are before the target instruction
	while(foo) {

		if(foo->begin_insn->new_addr > target->new_addr) {
			break;
		}

		prev = foo;
		foo = foo->next;
	}

	foo = prev;

	if (foo) {
		// Only update the size of the function that contains the target instruction
		foo->symbol->size += shift;
	}

	while(foo) {

		instr = foo->begin_insn;
		while(instr) {

			// Skip instructions that come before 'target'
			if(instr->new_addr <= target->new_addr) {
				instr = instr->next;
				continue;
			}

			// instr->i.x86.addr = instr->new_addr += shift;
			instr->new_addr += shift;

			// [SE] Updates the relocation entry to reflect the address shift
			if (instr->reference) {
				instr->reference->relocation.offset += shift;
			}
			// [SE] TODO: Hackish way to check for relocation from .text to .rodata, find better one
			if (instr->pointedby && !strncmp((const char *)instr->pointedby->name, ".text", 5)) {
				instr->pointedby->relocation.addend += shift;
			}
			// [/SE]

			jump_node = instr->targetof.first;
			while(jump_node) {
				jump = jump_node->elem;

				if (jump->new_addr < target->new_addr) {
					set_jump_displacement(jump, instr);
				}

				jump_node = jump_node->next;
			}

			hnotice(6, "Instruction '%s' at address <%#08llx> (size %u) shifted to new address <%#08llx>\n",
				instr->i.x86.mnemonic, instr->new_addr - shift, instr->size, instr->new_addr);

			instr = instr->next;
		}

		hnotice(4, "Function '%s' updated to <%#08llx> (%d bytes)\n",
			foo->symbol->name, foo->begin_insn->new_addr, foo->symbol->size);

		foo = foo->next;
	}

	// update all the relocation that ref instructions
	// beyond the one instrumented. (ie. in case of switch tables)
	// hnotice(4, "Check relocation symbols\n");

	/*sym = PROGRAM(symbols);
	while(sym) {

		// Looks for refrences which applies to .text section only
		if(!strncmp((const char *)sym->name, ".text", 5)) {

			// Update only those relocation beyond the code affected by current instrumentation and version
			if(sym->relocation.addend > (long long)(target->new_addr - shift) && sym->version == PROGRAM(version)) {

				sym->relocation.addend += shift;

				printf("update .rela.rodata :: offset= %08llx, instr_addr= %08llx (%08llx), addend=%lx (%lx %+d), version=%d(%d)\n",
					sym->relocation.offset, target->new_addr, target->new_addr - shift, sym->relocation.addend, sym->relocation.addend-shift, shift, sym->version, PROGRAM(version));

				hnotice(6, "Relocation to symbol %d (%s) at offset %#08llx addend updated %#0lx (%+d)\n",
					sym->index, sym->name, sym->position, sym->relocation.addend, shift);
			}
		}

		sym = sym->next;
	}*/
}

/**
 * Updates jump displacements in accordance with the new addresses of instructions.
 * It is advisable to call this function only after addresses have already been
 * recomputed (i.e. after calling <em>update_instruction_addresses</em>), otherwise
 * displacements will be wrong and the control flow correctness of the instrumented
 * logic cannot be preserved.
 *
 * @author Davide Cingolani
 * @author Simone Economo
 */
void update_jump_displacements(int version) {
	function *foo;
	insn_info *instr;
	// insn_info *jumpto;

	// unsigned int offset;

	// unsigned int size;
	unsigned int old_size; // [SE]

	long delta;
	long jump_displacement;

	unsigned char bytes[6];

	insn_info_x86 *x86;

	hnotice(4, "Update jump displacements\n");

	foo = PROGRAM(v_code)[version];
	while(foo) {

		hnotice(5, "In function '%s'\n", foo->name);

		instr = foo->begin_insn;
		while(instr != NULL) {

			if(IS_JUMP(instr) && instr->jumpto != NULL) {
				// offset = x86->opcode_size;
				// size = x86->insn_size - x86->opcode_size - x86->disp_size;
				old_size = instr->size; // [SE]

				// The expression (insn->new_addr + insn->size) gives the value of %rip.
				// By subtracting it from the address of the target instruction, we obtain
				// the jump displacement
				jump_displacement = instr->jumpto->new_addr - (instr->new_addr + instr->size);

				hnotice(6, "Jump instruction at <%#08llx> (originally <%#08llx>) +%#0llx points to instruction '%s' at <%#08llx> (originally <%#08llx>)\n",
					instr->new_addr, instr->orig_addr, (unsigned long long) jump_displacement,
					instr->jumpto->i.x86.mnemonic, instr->jumpto->new_addr, instr->jumpto->orig_addr);

				if (PROGRAM(insn_set) == X86_INSN) {
					x86 = &(instr->i.x86);

					// TODO: Must implement support to near and far jump!
					// Near jumps will use a relative offset, whereas far jumps use an absolute one
					// this could not be embedded directly relying on the jumpto instruction refs
					// cause this would give only the absolute address.

					// TODO: check if this would work!
					// prefix 0xff refers to an absolute jump instruction, hence the full jumpto instruction address
					// must be used instead of the relative offset displacement

					// If the jump instruction is a short jump, we must check whether the single 8-bit
					// displacement is big enough to hold the new value for the jump displacement.
					// In the negative case, we must replace the short jump with a long jump.
					if ((x86->opcode[0] & 0xf0) == 0x70 || x86->opcode[0] == 0xeb) {

						if (jump_displacement < -128 || jump_displacement > 128) {
							// We need to substitute the short jump with a long one

							hnotice(6, "Short jump at address <%#08llx> will overflow\n", instr->new_addr);

							bzero(bytes, sizeof(bytes));

							// TODO: embeddare l'update del displacement in questo modo non è sicuro
							if(x86->opcode[0] == 0xeb) {
								// Unconditional jump
								bytes[0] = 0xe9;

								// jump_displacement -= 3;
								// memcpy(bytes+1, &jump_displacement, 4);
							} else {
								// Conditional jump
								bytes[0] = 0x0f;
								bytes[1] = 0x80 | (x86->opcode[0] & 0xf);

								// jump_displacement -= 4;
								// memcpy(bytes+2, &jump_displacement, 4);
							}

							hnotice(6, "Short jump at <%#08llx> (originally <%#08llx>) will be converted to a long jump:\n",
								instr->new_addr, instr->orig_addr/*, jump_displacement */);

							hdump(6, "FROM", instr->i.x86.insn, instr->size);
							hdump(6, "TO", bytes, sizeof(bytes));

							substitute_instruction_with(instr, bytes, sizeof(bytes), &instr);

							// x86 = &(instr->i.x86);
							// offset = x86->opcode_size;
							// size = x86->insn_size - x86->opcode_size;
							delta = (instr->size - old_size);

							// Updating the jump instruction will also change its size, thus the displacement
							// has to be updated again in order to take into account the size increment

							// [SE] The new jump displacement gets inserted into the instruction
							// by the end of the iteration.
							shift_instruction_addresses(instr, delta);

							if (instr->new_addr < instr->jumpto->new_addr) {
								jump_displacement += delta;
							}
							// [/SE]
						}
					}

					set_jump_displacement(instr, instr->jumpto);
					// memcpy((x86->insn + offset), &jump_displacement, size);

					// hnotice(1, "Long jump displacement of instruction at address <%#08llx> updated to %#0llx\n",
					// 	instr->new_addr, jump_displacement);
				}

				// TODO: Embedded CALL instructions (i.e. for local functions) could be taken into account
				// in the same way as JUMP ones: their offsets can be generated directly into the code,
				// instead of using relocation

			}

			instr = instr->next;
		}

		foo = foo->next;
	}
}

