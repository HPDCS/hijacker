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
insn_info *find_insn(function *func, unsigned long long addr, insn_address_type type) {
	insn_info *instr;

	if (!func) {
		func = PROGRAM(code);
	}

	while (func) {

		if (func->next) {
			if (func->next->insn->orig_addr <= addr) {
				func = func->next;
				continue;
			}
			else if (func->next->insn->new_addr <= addr) {
				func = func->next;
				continue;
			}
		}

		instr = func->insn;
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

insn_info *find_last_insn(function *functions) {
	function *func;
	insn_info *instr;

	func = functions;
	while(func->next) {
		func = func->next;
	}

	instr = func->insn;
	while(instr->next) {
		instr = instr->next;
	}

	return instr;
}


/**
 * Creates a new instruction node starting from an array of bytes which represents
 * its raw content.
 *
 * @param bytes The array of bytes representing the raw content of the instruction.
 * @param pos Pointer to an integer representing the current position within
 * the <em>bytes</em> stream.
 * @param final Pointer to a variable which holds the pointer to the descriptor
 * of the newly parsed instruction.
 */
static void parse_instruction_bytes(unsigned char *bytes, unsigned long int *pos, insn_info **final) {
	insn_info *instr;
	int flags;

	if(bytes == NULL || pos == NULL) {
		hinternal();
	}

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
	// insn_info *pivot;
	function *func;

	// TODO: debug
	/*hprint("ISTRUZIONE: '%s' <%#08lx> -- op_size=%d, disp_off=%d, jump_dest=%d, size=%d\n", x86->mnemonic, x86->addr,
			x86->opcode_size, x86->disp_offset, x86->jump_dest, x86->insn_size);*/

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
		// pivot = target;
	}

	// Update instruction references
	// since we are adding a new instruction, the shift amount
	// is equal to the instruction's size
	// update_instruction_addresses(pivot, instr->size);

	//func = get_function(target);
	//hnotice(4, "Inserted a new instruction node %s the instruction at offset <%#08lx> in function '%s'\n", mode == INSERT_AFTER ? "after" : "before", target->new_addr, func->symbol->name);
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
int substitute_instruction_with(insn_info *target, unsigned char *binary, size_t size, insn_info **last) {
	insn_info *instr;
	unsigned long int pos = 0;
	unsigned int old_size;
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

	// we have to update all the references
	// delta shift should be the: d = (new size - old size) [signed, obviously]
	// old_size = target->size;
	// shift_instruction_addresses(instr, (size - old_size));

	// count += insert_instructions_at(instr, binary + pos, size - pos, INSERT_AFTER, last);

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
void add_call_instruction(insn_info *target, unsigned char *func, insn_insert_mode mode, insn_info **instr) {
	symbol *sym;
	unsigned char call[5];

	bzero(call, sizeof(call));
	switch (PROGRAM(insn_set)) {
		case X86_INSN:
			call[0] = 0xe8;
		break;
	}

	// Checks and creates the symbol name
	sym = create_symbol_node(func, SYMBOL_UNDEF, SYMBOL_GLOBAL, 0);

	// Adds the instruction to the binary representation
	// WRANING! We MUST add the instruction BEFORE to create
	// the new rela node, otherwise the instruction's address
	// will not be coherent anymore once at the amitting step
	insert_instructions_at(target, call, sizeof(call), mode, instr);
	//insert_insn_at(target, instr, where);

	// Once the instruction has been inserted into the binary representation
	// and each address and reference have been properly updated,
	// create a new RELA entry
	instruction_rela_node(sym, *instr, RELOCATE_RELATIVE_32);
}


/**
 * Clones an instruction descriptor.
 *
 * @param insn Pointer to the instruction descriptor to clone.

 * @return Pointer to the clone instruction descriptor.
 */
insn_info * clone_instruction (insn_info *insn) {
	insn_info *clone;

	clone = (insn_info *) calloc(sizeof(insn_info), 1);
	if(!clone) {
		herror(true, "Out of memory!\n");
	}

	memcpy(clone, insn, sizeof(insn_info));

	clone->jumpto = NULL;
	clone->targetof.first = clone->targetof.last = NULL;
	clone->jumptable.size = 0;
	clone->jumptable.entry = NULL;
	clone->virtual = NULL;

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
insn_info * clone_instruction_list (insn_info *insn) {
	insn_info *clone, *head;

	if(!insn)
		return NULL;

	head = clone = clone_instruction(insn);
	clone->prev = NULL;
	insn = insn->next;

	while(insn) {
		clone->next = clone_instruction(insn);
		clone->next->prev = clone;
		clone = clone->next;
		insn = insn->next;
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
		jump->orig_addr, jump->new_addr, target, target->orig_addr, target->new_addr);
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
		jump->orig_addr, jump->new_addr, entry, entry->orig_addr, entry->new_addr, idx);
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
		virtual->pointedby->relocation.ref_insn = virtual;

		target->pointedby = NULL;

		// virtual->reference->relocation.offset = virtual->new_addr;
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
void update_instruction_addresses(void) {
	function *foo;
	insn_info *instr;

	unsigned long long offset;
	unsigned long long old_offset;
	unsigned long long foo_size;

	long long rela_offset;
	long long rela_addend;

	hnotice(4, "Recalculate instructions' addresses\n");

	// Instruction addresses are recomputed from scratch starting from the very beginning
	// of the code section.
	foo = PROGRAM(code);
	offset = 0;
	while(foo) {

		hnotice(5, "Updating instructions in function '%s'\n", foo->name);

		foo_size = 0;

		instr = foo->insn;
		while(instr != NULL) {

			old_offset = instr->new_addr;
			// instr->i.x86.addr = instr->new_addr = offset;
			instr->new_addr = offset;

			if (instr->reference) {
				rela_offset = instr->reference->relocation.offset - instr->new_addr;
			}
			else {
				rela_offset = 0;
			}

			offset += instr->size;
			foo_size += instr->size;

			// [SE] Updates the relocation entry to reflect the address update
			if (instr->reference) {
				instr->reference->relocation.offset = instr->new_addr + rela_offset;
			}
			// [SE] TODO: Hackish way to check for relocation from .text to .rodata, find better one
			if (instr->pointedby && !strncmp((const char *)instr->pointedby->name, ".text", 5)) {
				instr->pointedby->relocation.addend = instr->new_addr;
			}
			// [/SE]

			hnotice(6, "Instruction '%s' <%#08llx> at old address <%#08llx> (size %u) has new address <%#08llx>\n",
				instr->i.x86.mnemonic, instr, old_offset, instr->size, instr->new_addr);

			instr = instr->next;
		}

		foo->symbol->size = foo_size;

		hnotice(4, "Function '%s' updated to <%#08llx> (%d bytes)\n",
			foo->symbol->name, foo->insn->new_addr, foo->symbol->size);

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

		if(foo->insn->new_addr > target->new_addr) {
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

		instr = foo->insn;
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
			foo->symbol->name, foo->insn->new_addr, foo->symbol->size);

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
void update_jump_displacements(void) {
	function *foo;
	insn_info *instr;
	// insn_info *jumpto;

	unsigned int offset;

	unsigned int size;
	unsigned int old_size; // [SE]

	long delta;
	long jump_displacement;

	unsigned char bytes[6];

	insn_info_x86 *x86;

	hnotice(4, "Update jump displacements\n");

	foo = PROGRAM(code);
	while(foo) {

		hnotice(5, "In function '%s'\n", foo->name);

		instr = foo->insn;
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
					instr->new_addr, instr->orig_addr, jump_displacement,
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
								instr->new_addr, instr->orig_addr, jump_displacement);

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



/**
 * Substitutes one instruction with another.
 * This function substitutes the instruction pointed to by the <em>target</em> instruction descriptor with
 * the bytes passed as argument as well. After new instruction is swapped, all the others are accordingly shifted to
 * the relative offset (positive or negative) introduced by the difference between the two sizes.
 * Note: This function will call the disassembly procedure in order to correctly parse the instruction bytes passed as
 * argument. This is a fundamental step to retrieve instruction's metadata, such as jump destination address,
 * displacement offset, opcode size and so on. Without these information future emit step will fail to correctly
 * relocates and links jump instructions together.
 *
 * @param target Target instruction's descriptor pointer.
 * @param insn Pointer to the descriptor of the instruction to substitute with.
 */
static void substitute_insn_with(insn_info *target, insn_info *instr) {

	// we have to update all the references
	// delta shift should be the: d = (old size - the new one) [signed, obviously]

	// Copy addresses
	instr->orig_addr = target->orig_addr;
	instr->new_addr = target->new_addr;

	// Update references
	instr->prev = target->prev;
	instr->next = target->next;
	if(target->prev)
		target->prev->next = instr;
	if(target->next)
		target->next->prev = instr;

	// update_instruction_addresses(instr, (instr->size - target->size));

	//func = get_function(target);
	//hnotice(4, "Substituting instruction at address <%#08lx> in function '%s'\n", target->orig_addr, func->symbol->name);
}
