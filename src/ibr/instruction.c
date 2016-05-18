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
* @brief Module to handle instructions in the Intermediate Representation
* @author Davide Cingolani
* @author Alessandro Pellegrini
* @author Roberto Vitali
* @author Simone Economo
* @date July 11, 2014
*/

#include <stdlib.h>
#include <string.h>
#include <strings.h>

#include <hijacker.h>
#include <prints.h>
#include <ibr.h>
#include <instruction.h>

#include <x86/x86.h>
#include <elf/handle-elf.h> // [SE] TODO: creare un multiplexer per creare entry di rilocazione


#define MAX_LOOKBEHIND		10 // [SE] Used while reverse-parsing instruction to resolve jump tables



/**
 * Seeks the instruction descriptor associated with a given instruction address
 * (either original or new) in the entire program or within a desired function.
 *
 * @param func Pointer to the function descriptor that contains the instruction,
 * or <em>NULL</em> to search throughout the entire program.
 * @param addr Address of the instruction to be found.
 * @param type Integer constant representing which type of address has been
 * passed through the <em>addr</em> parameter.
 *
 * @return Pointer to the instruction descriptor found, if any, or <em>NULL</em>.
 *
 * @author Simone Economo
 */
// [SE] This should be name `find_insn_from_func`
insn_info *find_insn(function *func, unsigned long long addr, insn_address_type type) {
	insn_info *instr;

	if (!func) {
		func = PROGRAM(code);
	}

	while (func) {

		if (func->next) {
			if (func->next->begin_insn->new_addr <= addr) {
				func = func->next;
				continue;
			}
			else if (func->next->begin_insn->new_addr <= addr) {
				func = func->next;
				continue;
			}
		}

		instr = func->begin_insn;
		while(instr) {
			if (instr->orig_addr == addr && type == ORIG_ADDR) {
				return instr;
			}
			else if (instr->new_addr == addr && type == NEW_ADDR) {
				return instr;
			}

			instr = instr->next;
		}

		func = func->next;
	}

	return NULL;
}

// [SE] This should be named `find_insn`
insn_info *find_insn_cool(insn_info *head, unsigned long long addr) {
	insn_info *instr;

	for (instr = head; instr; instr = instr->next) {
		if (instr->orig_addr <= addr
		 && instr->orig_addr + instr->size > addr) {
			return instr;
		}
	}

	return NULL;
}

insn_info *find_last_insn(function *functions) {
	function *func;
	insn_info *instr;

	func = functions;
	while(func->next) {
		func = func->next;
	}

	instr = func->begin_insn;
	while(instr->next) {
		instr = instr->next;
	}

	return instr;
}


// TODO: cambiare la funzione in modo da iterare sul numero di byte passati
//		dovrebbe quindi restituire una catena già formata di istruzioni
/**
 * Creates a new instruction node starting from an array of bytes which represents
 * its raw content.
 *
 * @author Davide Cingolani
 *
 * @param bytes The array of bytes representing the raw content of the instruction.
 * @param pos Pointer to an integer representing the current position within
 * the <em>bytes</em> stream.
 * @param final Pointer to a variable which holds the pointer to the descriptor
 * of the newly parsed instruction.
 */
 // TODO: definire statica di nuovo!!!
void parse_instruction_bytes(unsigned char *bytes, unsigned long int *pos, insn_info **final) {
	insn_info *instr;
	int flags;

	if(bytes == NULL || pos == NULL) {
		hinternal();
	}

	flags = 0;

	// parse the input bytes to correctly understand which instruction
	// they represents
	switch(PROGRAM(insn_set)) {
	case X86_INSN:
		if(ELF(is64)) {
			flags |= DATA_64;
			flags |= ADDR_64;
		} else {
			flags |= DATA_32;
			flags |= ADDR_32;
		}

		instr = *final;

		// Interprets the current binary code
		x86_disassemble_instruction(bytes, pos, &instr->i.x86, flags);

		hnotice(6, "%#08lx: %s (%d)\n", instr->i.x86.initial, instr->i.x86.mnemonic, instr->i.x86.opcode_size);

		// Aligns the instruction descriptor metadata to the actual values
		instr->flags = instr->i.x86.flags;
		// [SE] TODO: Decommentando emerge un bug
		// instr->new_addr = instr->orig_addr = instr->i.x86.initial;
		instr->size = instr->i.x86.insn_size;
		instr->opcode_size = instr->i.x86.opcode_size;

		hnotice(5, "A new '%s' instruction is parsed (%d bytes)\n", instr->i.x86.mnemonic, instr->size);
		hdump(6, "Raw bytes", instr->i.x86.insn, instr->size);

		break;
	}
}


/**
 * Links a newly created instruction descriptor to the intermediate representation,
 * before or after another descriptor.
 *
 * @param target Pointer to the instruction descriptor of the instruction
 * relative to which insertion will be performed.
 * @param instr Pointer to the newly created instruction descriptor.
 * @param mode Integer constant representing whether the instruction is inserted
 * before or after the target one.
 */
static inline void insert_insn_at(insn_info *target, insn_info *instr, insn_insert_mode mode) {

	if (mode == INSERT_BEFORE) {
		instr->next = target;
		instr->prev = target->prev;

		if (target->prev) {
			target->prev->next = instr;
		}

		target->prev = instr;
		// pivot = instr;
	}
	else if (mode == INSERT_AFTER) {
		instr->next = target->next;
		instr->prev = target;

		if (target->next) {
			target->next->prev = instr;
		}

		target->next = instr;
	}
}



/**
 * Creates new instruction descriptors and adds them to the corresponding
 * instructions chain.
 *
 * @param target Pointer to the instruction descriptor relative to which the
 * insertion will be performed.
 * @param bytes Pointer to a buffer of bytes representing the instructions to add
 * in the machine-dependent format.
 * @param size Instructions length in byte (hence of the <em>bytes</em> parameter).
 * @param mode Integer constant representing whether the instruction is inserted
 * before, after or in place of the target one.
 * @param last Pointer to a variable which will hold the pointer to the descriptor
 * of the last newly inserted instruction.
 *
 * @return Number of newly inserted instructions.
 */
int insert_instructions_at(insn_info *target, unsigned char *binary, size_t size, insn_insert_mode mode, insn_info **last) {
	insn_info *instr;
	unsigned long int pos;
	int count;

	hnotice(4, "Inserting instructions from raw binary code (%zd bytes) %s the instruction at %#08llx\n",
		size, mode == INSERT_BEFORE ? "before" : "after", target->orig_addr);
	hdump(5, "Binary", binary, size);

	// Pointer 'binary' may contains more than one instruction:
	// in this case, the behavior is to convert the whole binary
	// and add the relative instructions to the representation
	pos = 0;
	count = 0;

	while(pos < size) {
		// Packs the next instruction
		instr = calloc(sizeof(insn_info), 1);

		// Calls the disassembly procedure in order to correctly parse
		// the instruction bytes passed as argument.
		// This is a fundamental step to retrieve instruction's metadata,
		// such as jump destination address, displacement offset, opcode size
		// and so on.
		// Without these information, future emit step will fail to correctly
		// relocates and links jump instructions together.
		parse_instruction_bytes(binary, &pos, &instr);

		// Useful in order to be able to retrieve the section from
		// the just added instruction
		instr->orig_addr = instr->new_addr = target->new_addr;

		// Adds the newly created instruction descriptor to the
		// intermediate representation
		insert_insn_at(target, instr, mode);

		target = instr;
		count++;
	}

	if (last) {
		*last = instr;
	}

	hnotice(4, "Inserted %d instruction %s the target <%#08llx>\n",
		count, mode == INSERT_BEFORE ? "before" : "after", target->new_addr);

	return count;
}


/**
 * Substitutes one instruction with another.
 *
 * @param target Pointer to the target instruction descriptor to be replaced.
 * @param bytes Pointer to a buffer of bytes representing the new instruction in
 * the machine-dependent format.
 * @param size Instruction length in byte (hence of the <em>bytes</em> parameter).
 *
 * @return Number of newly inserted instructions.
 */
int substitute_instruction_with(insn_info *target, unsigned char *binary, size_t size) {
	insn_info *instr;
	unsigned long int pos = 0;
	int count;

	hnotice(4, "Substituting target instruction at %#08llx with binary code\n", target->new_addr);
	hdump(5, "Old instruction", target->i.x86.insn, target->size);
	hdump(5, "Binary code", binary, size);

	// First instruction met will substitute the current target,
	// whereas the following ones have to be inserted just after it
	pos = 0;
	count = 1;
	instr = target;

	parse_instruction_bytes(binary, &pos, &instr);

	hnotice(4, "Target instruction substituted with %d instructions\n", count);

	return count;
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
void add_call_instruction(insn_info *target, char *name, insn_insert_mode mode, insn_info **instr) {
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
	sym = find_symbol_by_name(name);
	if (sym == NULL) {
		sym = symbol_create(name, SYMBOL_UNDEF, SYMBOL_GLOBAL, sec, 0);
	}

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


void add_jump_instruction(insn_info *target, char *name, insn_insert_mode mode, insn_info **instr) {
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
 * Clones an instruction descriptor.
 *
 * @param insn Pointer to the instruction descriptor to clone.

 * @return Pointer to the clone instruction descriptor.
 */
insn_info * clone_instruction (insn_info *instr) {
	insn_info *clone;

	clone = (insn_info *) calloc(sizeof(insn_info), 1);
	if(!clone) {
		herror(true, "Out of memory!\n");
	}

	memcpy(clone, instr, sizeof(insn_info));

	// Reset the meta-data of new instruction clone
	clone->jumpto = NULL;
	clone->targetof.first = clone->targetof.last = NULL;
	clone->jumptable.size = 0;
	clone->jumptable.entry = NULL;
	clone->virtual = NULL;
	clone->reference.first = clone->reference.last = NULL;
	clone->pointedby.first = clone->pointedby.last = NULL;

	clone->parent = instr;

	return clone;
}


/**
 * Clones the list of instruction descriptors passed as parameter.
 *
 * @param insn Pointer to the first instruction descriptor of the list that
 * will be cloned.
 *
 * @return Pointer to the first instruction descriptor of the clone list.
 */
insn_info * clone_instruction_list (insn_info *instr) {
	insn_info *clone, *head;

	if(!instr)
		return NULL;

	head = clone = clone_instruction(instr);
	clone->prev = NULL;
	instr = instr->next;

	while(instr) {
		clone->next = clone_instruction(instr);
		clone->next->prev = clone;
		clone = clone->next;
		instr = instr->next;
	}

	return head;
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
	symbol *rela;

	unsigned int idx;

	while( !ll_empty(&target->targetof) ) {
		jump = ll_pop_first(&target->targetof);

		ll_push(&virtual->targetof, jump);

		if (jump->jumpto) {
			jump->jumpto = virtual;

			hnotice(3, "%s instruction at <%#08llx> (<%#08llx>) linked to virtual instruction at address <%#08llx> (<%#08llx>)\n",
				IS_JUMP(jump) ? "Jump" : "Call",
				jump->orig_addr, jump->new_addr, virtual->orig_addr, virtual->new_addr);
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

	// Update relocations that originally pointed target to refer
	// its virtual replacement
	while (!ll_empty(&target->pointedby)) {
		rela = ll_pop(&target->pointedby);

		rela->relocation.target_insn = virtual;

		ll_push(&virtual->pointedby, rela);
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

	bool start_found;
	bool size_found;

	backinstr = instr;
	sym = NULL;
	sec = NULL;
	callee = NULL;
	start = size = 0;

	// Code for indirect jumps (very very unreliable!)
	if (IS_JUMPIND(instr)) {
		start_found = size_found = false;

		// We keep searching for the start address and the size of the jump table
		backinstr = instr;
		i = 0;

		while(backinstr && i < MAX_LOOKBEHIND && (!start_found || !size_found)) {

			if (!start_found && IS_MEMRD(backinstr)) {
				sym = instr_reference_weak(backinstr);

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
				sym = instr_reference_weak(backinstr);

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
			hnotice(5, "Function pointer to %s\n", callee->name);

			set_jumpto_reference(instr, callee->begin_insn);
		}

		else if (size) {
			hnotice(5, "Array named %s starting at %s + <%#08llx> and sized %lu\n",
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

void link_jump_instructions(void) {
	function *func, *prev;
	insn_info *instr, *dest;

	static unsigned int index = 0;
	unsigned long long jmp_addr;

	function *callee;
	symbol *sym, *rela;

	hnotice(1, "Resolving jump and call instructions...\n");

	for (prev = NULL, func = PROGRAM(v_code)[PROGRAM(version)]; func;
	     prev = func, func = func->next) {
		// if (functions_overlap(prev, func)) {
		// 	continue;
		// }

		hnotice(2, "Resolve jumps/calls of function '%s'\n", func->name);

		for (instr = func->begin_insn; instr; instr = instr->next) {

			instr->index = index++;

			hnotice(6, "Inspecting instruction %s at %#08llx\n",
				instr->i.x86.mnemonic, instr->orig_addr);

			// ---------------------------------------------------------
			// JUMP instructions
			// ---------------------------------------------------------

			if (IS_JUMP(instr)) {

				hnotice(3, "Found jump instruction at <%#08llx> (<%#08llx>)\n",
					instr->orig_addr, instr->new_addr);

				if (IS_JUMPIND(instr)) {
					// If the instruction is an indirect jump, try to resolve its
					// associated jump table (currently only for switch-case statements)
					// NOTE: This is a very naive and loose algorithm that may fail
					// in several cases, and is not kitten-proof! Beware!
					resolve_jump_table(func, instr);
				}

				else if (!ll_empty(&instr->reference)) {
					// If the jump instruction has a relocation, simply skip the instruction;
					// the linker will be in charge to correctly handle it
					continue;
				}

				else {
					// The JUMP has a non-null embedded offset, from which we can derive
					// the effective jump address
					switch (PROGRAM(insn_set)) {
						case X86_INSN:
							if (instr->i.x86.jump_dest == 0) {
								// We expect a non-null embedded offset...
								hinternal();
							}
							jmp_addr = instr->orig_addr + instr->size + instr->i.x86.jump_dest;
							break;
						default:
							hinternal();
					}

					hnotice(6, "Jump to a local instruction at <%#08llx> detected\n", jmp_addr);

					dest = find_insn_cool(func->begin_insn, jmp_addr);

					if (!dest) {
						hinternal();
					}

					set_jumpto_reference(instr, dest);
				}

			}

			// ---------------------------------------------------------
			// CALL instructions
			// ---------------------------------------------------------

			else if (IS_CALL(instr)) {

				hnotice(3, "Found call instruction at <%#08llx> (<%#08llx>)\n",
					instr->orig_addr, instr->new_addr);

				if (IS_CALLIND(instr)) {
					// Handle indirect calls (tricky, uses the same naive algorithm
					// as for switch-case statements)
					resolve_jump_table(func, instr);

					continue;
				}

				else if (!ll_empty(&instr->reference)) {
					// NOTE: Not likely, but a call instruction may have multiple
					// associated relocations
					sym = instr->reference.first->elem;

					// We must check whether it is a CALL to a local function or not,
					// and act accordingly.

					if (sym->size == 0) {
						// The function is defined elsewhere (i.e. in a different file object)
						// meaning that the linker will be in charge to correctly handle it
						hnotice(4, "Call instruction at <%#08llx> (<%#08llx>) invokes external function, skipping\n",
							instr->orig_addr, instr->new_addr);
						continue;
					}

					// A CALL whose displacement is filled with a .text+addend relocation,
					// rather than a relocation toward a FUNCTION symbol, may result
					// from incremental linking. Consider two LOCAL functions with the
					// same name in two different objects. When linking those object
					// with '-r' a third object file will be produced with two LOCAL
					// functions, both with the same name.
					//
					// To distinguish between an invocation to a function and one
					// to the other function, the linker modifies all relocations.
					// Specifically, it resorts to a .text+addend schema. This will
					// guarantee that the correct function be called, always.
					// Note that the same mechanism is also used by the linker for
					// other kind of same-name symbols (e.g., OBJECT ones).
					//
					// Unfortunately, this causes problem to our parsing of the instruction
					// jump/call graph, as well as the CFG.

					if (sym->type == SYMBOL_SECTION && sym->sec->type == SECTION_CODE) {
						// sym punta ad una sezione testo al cui offset di rilocazione
						// è indirettamente associata una funzione.
						// è necessario trovare la funzione destinazione, creare un nuovo
						// simbolo di rilocazione verso la funzione a partire dall'istruzione
						// corrente ed eliminare il simbolo (fake) che rappresenta la rilocazione
						// verso .text dalla stessa istruzione

						// FIXME: Not sure 'size - opcode_size' is portable across ISAs
						jmp_addr = sym->relocation.addend + instr->size - instr->opcode_size;

						callee = find_func_cool(sym->sec, jmp_addr);

						hnotice(4, "Call instruction at <%#08llx> invokes function through indirect relocation\n", instr->orig_addr);

						if (!callee) {
							hinternal();
						}

						for (rela = PROGRAM(symbols); rela->next; rela = rela->next) {
							if (rela->next == sym) {
								rela->next = sym->next;
								break;
							}
						}

						ll_pop_first(&instr->reference);
						free(sym);

						symbol_instr_rela_create(callee->symbol, instr, RELOC_PCREL_32);
					} else {
						callee = sym->func;

						if (!callee) {
							hinternal();
						}
					}
				}

				else {
					// If the CALL has a non-null embedded offset, it is a call to
					// a local function and the format is the same as a jump.
					switch (PROGRAM(insn_set)) {
						case X86_INSN:
							if (instr->i.x86.jump_dest == 0) {
								// We expect a non-null embedded offset...
								hinternal();
							}
							jmp_addr = instr->orig_addr + instr->size + instr->i.x86.jump_dest;
							break;
						default:
							hinternal();
					}

					hnotice(6, "Call to a local function at <%#08llx> detected\n", jmp_addr);

					callee = find_func_cool(func->symbol->sec, jmp_addr);

					if (!callee) {
						hinternal();
					}

					// The instruction is translated into a zero'd CALL with an associated
					// relocation entry.
					switch(PROGRAM(insn_set)) {
						case X86_INSN:
							memset(instr->i.x86.insn + instr->opcode_size, 0, (instr->size - instr->opcode_size));
							// break;
					}

					// At this point 'callee' will point to the destination function
					// relative to the call; the only thing we have to do is to treat
					// local function calls as relocation entities.
					sym = callee->symbol;

					symbol_instr_rela_create(sym, instr, RELOC_PCREL_32);
				}

				// CALL to local function detected, augment the intermediate representation
				// with the appropriate linking between instructions.
				hnotice(4, "Callee function '%s' at <%#08llx> found\n",
					callee->name, callee->begin_insn->orig_addr);

				set_jumpto_reference(instr, callee->begin_insn);
			}

		}
	}


}


// FIXME: Questa funzione sancisce il passaggio da un address space
// pseudo-segmentato (offset_sezione + offset_istruzione) a uno
// totalmente lineare (offset_istruzione)... verificare che questa
// operazione venga svolta correttamente (e verificare che sia
// effettivamente necessaria...)
/**
 * Updates all the instruction addresses, starting from the beginning of the
 * program all the way to its end. An offset variable takes into account the
 * sizes of each instruction already met, and incrementally determines the final
 * address of the next instruction. Notice that the function only updates the
 * new address, leaving the original address untouched for debugging purposes.
 *
 * @author Davide Cingolani
 * @author Simone Economo
 */
void update_instruction_addresses(int version) {
	function *foo, *prev_foo;
	insn_info *instr;

	unsigned long long offset;
	unsigned long long old_offset;
	unsigned long long foo_size;
	unsigned long long foo_offset;

	ll_node *rela_node;
	symbol *rela, *alias;

	long long rela_offset;

	// Instruction addresses are recomputed from scratch starting from
	// the very beginning of the code section.
	offset = 0;
	prev_foo = NULL;

	for (foo = PROGRAM(v_code)[version]; foo;  prev_foo = foo, foo = foo->next) {
		foo_size = 0;

		// // Verify the case of multiple symbols pointing to the same code
		// // If there is an instruction shared with two of more functions
		// // a call to `find_func_by_instr` will return a non-NULL value.
		// // If this is the case, we must skip the update since it has been
		// // already done previously
		// if (functions_overlap(foo, prev_foo)) {
		// 	foo->symbol->offset = prev_foo->symbol->offset;
		// 	foo->symbol->size = prev_foo->symbol->size;

		// 	hnotice(3, "Function '%s' at <%#08llx> is an overloading of '%s'; no instructions are updated\n",
		// 		foo->name, foo->symbol->offset, prev_foo->name);

		// 	continue;
		// }

		hnotice(3, "Updating instructions in function '%s'\n", foo->name);

		foo_offset = offset;

		for (instr = foo->begin_insn; instr; instr = instr->next) {

			old_offset = instr->new_addr;
			instr->new_addr = offset;

			offset += instr->size;
			foo_size += instr->size;

			hnotice(4, "Instruction '%s' <%#08llx> at old address <%#08llx> (size %u) has new address <%#08llx>\n",
				instr->i.x86.mnemonic, (unsigned long long) instr, old_offset, instr->size, instr->new_addr);

			// Updates the relocation entry to reflect the address update
			for (rela_node = instr->reference.first; rela_node; rela_node = rela_node->next) {
				rela = rela_node->elem;
				rela_offset = rela->relocation.offset;

				// rela->relocation.offset = instr->new_addr + instr->opcode_size;
				rela->relocation.offset += instr->new_addr - old_offset;

				hnotice(5, "Relocation in '%s' at old offset <%#08llx> updated to new offset <%#08llx>\n",
					instr->i.x86.mnemonic, rela_offset, rela->relocation.offset);
			}

			// FIXME: Hackish way to check for relocation from .text to .rodata, find better one
			for (rela_node = instr->pointedby.first; rela_node; rela_node = rela_node->next) {
				rela = rela_node->elem;
				rela_offset = rela->relocation.addend;

				rela->relocation.addend += instr->new_addr - old_offset;

				hnotice(5, "Relocation to '%s' at old addend <%#08llx> updated to new addend <%lx>\n",
					instr->i.x86.mnemonic, rela_offset, rela->relocation.addend);
			}
		}


		for (alias = PROGRAM(symbols); alias != NULL; alias = alias->next) {
			if (alias->type != SYMBOL_FUNCTION || alias->sec != foo->symbol->sec)
				continue;

			if (alias->offset == foo->symbol->offset) {
				alias->offset = foo_offset;
				alias->size = foo_size;
			}
		}

		foo->symbol->offset = foo_offset;
		foo->symbol->size = foo_size;

		hnotice(4, "Function '%s' updated to <%#08llx> (%d bytes)\n",
			foo->symbol->name, foo->begin_insn->new_addr, foo->symbol->size);
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

	if (IS_CALL(jump)) {
		// We enforce a liking discipline here: CALL instructions
		// should always have associated relocation entries
		hinternal();
	}

	switch (PROGRAM(insn_set)) {
		case X86_INSN:
			x86 = &(jump->i.x86);

			size = jump->size - x86->opcode_size - x86->disp_size;
			displacement = target->new_addr - (jump->new_addr + jump->size);

			memcpy((x86->insn + x86->opcode_size), &displacement, size);
		break;

		default:
			hinternal();
	}

	hnotice(4, "Jump instruction at <%#08llx> (<%#08llx>) has updated displacement %#0llx\n",
		jump->orig_addr, jump->new_addr, displacement);
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
static void shift_instruction_addresses(insn_info *pivot, int shift) {
	function *func, *prev;
	insn_info *instr;

	ll_node *rela_node;
	symbol *rela;

	ll_node *jump_node;
	insn_info *jump;

	hnotice(4, "Shifting the addresses of instructions beyond <%#08llx> by %+d bytes\n",
		pivot->new_addr, shift);

	// Skip functions that are before the pivot instruction
	for (prev = NULL, func = PROGRAM(code); func; prev = func, func = func->next) {
		if (func->begin_insn->new_addr > pivot->new_addr) {
			break;
		}
	}

	if (prev != NULL) {
		// Update the size of the function that contains the pivot instruction
		prev->symbol->size += shift;
	}

	for (func = prev; func; func = func->next) {
		for (instr = func->begin_insn; instr; instr = instr->next) {

			// Skip instructions that come before 'pivot'
			if (instr->new_addr <= pivot->new_addr) {
				continue;
			}

			// Shift instruction address
			instr->new_addr += shift;

			// Shift relocation offsets/addends
			for (rela_node = instr->reference.first; rela_node; rela_node = rela_node->next) {
				rela = rela_node->elem;

				rela->relocation.offset += shift;
			}

			for (rela_node = instr->reference.first; rela_node; rela_node = rela_node->next) {
				rela = rela_node->elem;

				if (str_prefix(rela->name, ".text")) {
					rela->relocation.addend += shift;
				}
			}

			// Rewrite displacements of jumps that come before the pivot
			for (jump_node = instr->targetof.first; jump_node; jump_node = jump_node->next) {
				jump = jump_node->elem;

				// No need to insert an embedded displacement in CALLs,
				// let's leave it for the linker...
				if (!IS_CALL(jump) && jump->new_addr < pivot->new_addr) {
					set_jump_displacement(jump, instr);
				}
			}

			hnotice(6, "Instruction '%s' at address <%#08llx> (size %u) shifted to new address <%#08llx>\n",
				instr->i.x86.mnemonic, instr->new_addr - shift, instr->size, instr->new_addr);
		}

		hnotice(4, "Function '%s' updated to <%#08llx> (%d bytes)\n",
			func->symbol->name, func->begin_insn->new_addr, func->symbol->size);
	}
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

	size_t old_size;

	long delta, displacement;

	unsigned char bytes[8];

	insn_info_x86 *x86;

	if (PROGRAM(insn_set) != X86_INSN) {
		hinternal();
	}

	for (foo = PROGRAM(v_code)[version]; foo; foo = foo->next) {
		hnotice(3, "Update jump displacements in function '%s'\n", foo->name);

		for (instr = foo->begin_insn; instr; instr = instr->next) {
			if (IS_JUMP(instr) && instr->jumpto != NULL) {
				old_size = instr->size;

				// The expression `insn->new_addr + insn->size` gives
				// the value of %rip. By subtracting it from the address
				// of the target instruction, we obtain the displacement
				displacement = instr->jumpto->new_addr - (instr->new_addr + instr->size);

				hnotice(4, "Jump instruction at <%#08llx> (originally <%#08llx>) +%#0llx "
					"points to instruction '%s' at <%#08llx> (originally <%#08llx>)\n",
					instr->new_addr, instr->orig_addr, (unsigned long long) displacement,
					instr->jumpto->i.x86.mnemonic, instr->jumpto->new_addr, instr->jumpto->orig_addr);

				x86 = &(instr->i.x86);

				// There are two kind of jumps: near and far jumps.
				// Near (relative) jumps use a relative offset, whereas
				// far (absolute) jumps use an absolute one.
				// Another taxonomy entails the bit width of the jump
				// displacement fields. If the jump instruction is a
				// short jump, we must check whether the single 8-bit
				// displacement is big enough to hold the new value for
				// the jump displacement. In the negative case, we must
				// replace the short jump with a long jump.

				if ((x86->opcode[0] & 0xf0) == 0x70 || x86->opcode[0] == 0xeb) {
					// It is a short jump instruction
					hnotice(4, "It is a short instruction\n");

					if (displacement < (char) 0x80 || displacement > 0x7f) {
						// We need to substitute the short jump with a long one
						memset(bytes, '\0', sizeof(bytes));

						// TODO: embeddare l'update del displacement in questo modo non è sicuro
						if (x86->opcode[0] == 0xeb) {
							// Unconditional jump
							bytes[0] = 0xe9;
						} else {
							// Conditional jump
							bytes[0] = 0x0f;
							bytes[1] = 0x80 | (x86->opcode[0] & 0xf);
						}

						hnotice(4, "Short jump at <%#08llx> (originally <%#08llx>) will be converted to a long jump because %ld > %ld or < %d:\n",
							instr->new_addr, instr->orig_addr, displacement, 0x7f, (char) 0x80);
						hdump(6, "FROM", instr->i.x86.insn, instr->size);
						hdump(6, "TO", bytes, sizeof(bytes));

						substitute_instruction_with(instr, bytes, sizeof(bytes));

						delta = (instr->size - old_size);

						// Updating the jump instruction will also change the
						// instruction size, thus the address of subsequent
						// instructions has to be updated again in order to
						// take into account the size increment.

						// The new jump displacement gets inserted into the
						// instruction by the end of the iteration.
						shift_instruction_addresses(instr, delta);

						// if (instr->new_addr < instr->jumpto->new_addr) {
						// 	displacement += delta;
						// }
					}
				}

				set_jump_displacement(instr, instr->jumpto);
			}
		}
	}
}
