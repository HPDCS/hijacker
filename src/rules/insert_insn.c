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
* @file insert_insn.c
* @brief Module to add instructions in the Intermediate Representation
* @author Davide Cingolani
* @author Alessandro Pellegrini
* @author Roberto Vitali
*/

#include <stdlib.h>
#include <string.h>

#include <hijacker.h>
#include <prints.h>

#include <elf/handle-elf.h>

#include "insert_insn.h"


static function * get_function (insn_info *target) {
	function *cur, *prev;

	// TODO: da testare se funziona!!
	// find the function to which the instrumented instruction belongs
	cur = PROGRAM(code);
	while(cur) {
		if(cur->new_addr > target->new_addr) {
			break;
		}

		prev = cur;
		cur = cur->next;
	}

	return prev;
}


static void parse_instruction_bytes (char *bytes, unsigned long int *pos, insn_info **first) {
	insn_info *insn;
	int flags;

	// parse the input bytes to correctly understand which instruction
	// they represents
	switch(PROGRAM(insn_set)) {
	case X86_INSN:
		flags = ELF(is64) ? ADDR_64 | DATA_64 : ADDR_32 | DATA_32;

		// creates a new instruction node
		insn = (insn_info *) malloc(sizeof(insn_info));
		bzero(insn, sizeof(insn_info));

		if(!insn) {
			herror(true, "Out of memory!\n");
		}
		bzero(insn, sizeof(insn_info));

		// Interprets the current binary code
		x86_disassemble_instruction(bytes, pos, &insn->i.x86, flags);

		// Aligns the instruction descriptor metadata to the actual values
		insn->opcode_size = insn->i.x86.opcode_size;
		insn->size = insn->i.x86.insn_size;

		hnotice(5, "A new '%s' instruction is parsed\n", insn->i.x86.mnemonic);
		hdump(6, "Raw bytes", insn->i.x86.insn, insn->size);

		break;
	}

	*first = insn;
}


/**
 * Updates all the instruction addresses and references, either jump destinations and relocation entries.
 * Starting from the target instruction, that is the one newly created or subsituted, the function will
 * perform an update of all the addresses and refereces of the following instructions. Address is shifted
 * by the parameter 'shift'; this is an unsigned value. To properly work, it is needed that the newly
 * created instruction node has the right address, namely the one that should have in the final result.
 * Then, this function will eventually update the address of the other instructions, but the target's one
 * must be correctly set, already.
 *
 * @param func Function description to which the target instruction belongs
 * @param target Target instruction (either the substituted or newly created one)
 * @param shift (Signed) number of bytes by which to shift all the references
 */
static void update_instruction_references(function *func, insn_info *target, int shift) {
	insn_info *insn;
	insn_info *jumpto;
	insn_info_x86 *x86;
	symbol *sym;
	symbol *reference;
	section *sec;
	reloc *rel;
	function *foo;
	int old_offset;

	int offset;
	int size;
	long long jump_displacement;
	char jump_type;

	hnotice(3, "Updating instructions' references beyond the one intrumented... (shift = %+d)\n", shift);

	// updates the dimension of the function symbol
	//func->symbol->size += shift;

	// now, we have to update the addresses of all the remaining instructions in the function
	// ATTENZIONE! Non è corretto fare questo perché gli offset delle istruzioni sono a partire
	// dall'inizio della sezione .text quindi sarebbe necessario aggiornare TUTTI i riferimenti
	// e non solo quelli relativi alla funzione in questione (... a meno che non si cambi la
	// logica degli offset nel descrittore di istruzione a rappresentare lo spiazzamento
	// relativo all'interno della funzione di appartenenza, ma non so quali altri problemi comporta)
	hnotice(4, "Recalculate instructions' addresses\n");
	//hnotice(5, "Updating instructions in function '%s'\n", func->name);


/*	insn = target->prev;
	while(insn) {
		old_offset = insn->new_addr;
		insn->i.x86.addr = insn->new_addr += shift;

		hnotice(6, "Instruction '%s' at offset <%#08lx> shifted to new address <%#08lx>\n", insn->i.x86.mnemonic, old_offset,
				insn->new_addr);

		insn = insn->next;
	}
*/

	// Instruction addresse are recomputed from scratch starting from the very beginning
	// of the code section. Either a new instruction is inserted or substituted, an 'offset'
	// variable holds the incremental address which takes into account the sizes of each
	// instruction encountered.
	//foo = func;
	foo = PROGRAM(code);
	offset = foo->new_addr;
	while(foo) {
		hnotice(5, "Updating instructions in function '%s'\n", foo->name);

		insn = foo->insn;
		while(insn) {
			old_offset = insn->new_addr;
			insn->i.x86.addr = insn->new_addr = offset;
			offset += insn->size;
			//insn->i.x86.addr = insn->new_addr += shift;

			hnotice(6, "Instruction '%s' at offset <%#08lx> shifted to new address <%#08lx>\n", insn->i.x86.mnemonic, old_offset,
				insn->new_addr);

			insn = insn->next;
		}

		foo->new_addr = foo->insn->new_addr;
		foo->symbol->size = offset;

		hnotice(4, "Function size updated to %d\n", foo->symbol->size);

		foo = foo->next;
	}

	// update jump references, if any, from this function to end of code
	hnotice(4, "Check jump displacements\n");

	foo = PROGRAM(code);
	//foo = func;
	while(foo) {

		insn = foo->insn;
		while(insn) {

			if(IS_JUMP(insn)) {
				// XXX: in parse-elf.c:link_jump_instruction()
				// viene settato il campo jumpto...
				//~ jumpto = (insn_info *)insn->reference;
				jumpto = (insn_info *)insn->jumpto;
				x86 = &(insn->i.x86);

				offset = x86->opcode_size;
				size = x86->insn_size - x86->opcode_size;
				jump_displacement = jumpto->new_addr - (insn->new_addr + insn->size);
				// (insn->new_addr + insn->size) will give %rip value, then we have to subtract
				// the address of jump destination instruction

				hnotice(5, "Jump instruction at <%#08lx> (originally <%#08lx>) +%#0lx points to address %#08lx (originally %#08lx)\n",
					insn->new_addr, insn->orig_addr, jump_displacement, jumpto->new_addr, jumpto->orig_addr);

				// TODO: Must implement support to near and far jump!
				// Near jumps will use a relative offset, whereas far jumps use n absolute one
				// this could not be embeded directly relying on the jumpto instruction references
				// cause this wuold give only the absolute address.

				// TODO: check if this would work!
				// prefix 0xff refres to an absolute jump instruction, hence the full jumpto instruction address
				// must be used intead of the relative offset displacement

				if ((x86->opcode[0] & 0xf0) == 0x70 || x86->opcode[0] == 0xeb) {
					// for the short jump check it the jump is at more of 128 byte, otherwise
					// the single 8-bits displacement for the short jump is unsiffucient
					if (jump_displacement < -128 || jump_displacement > 128) {
						hnotice(5, "Short jump will overflow with new displacement %#0lx\n", jump_displacement);

						// in this case we need to substitute the short jump with a long one
						char bytes[6];
						bzero(bytes, sizeof(bytes));

						// TODO: differenza tra jump condizionale e non!!

						// updating the jump instruction, will also change its size, thus the displacement
						// has to be updated againg in order to take into account the size increment

						// TODO: embeddare l'update del displacement in questo modo non è sicuro
						if(x86->opcode[0] == 0xeb) {
							bytes[0] = 0xe9;

							jump_displacement -= 3;
							memcpy(bytes+1, &jump_displacement, 4);
						} else {
							bytes[0] = 0x0f;
							bytes[1] = 0x80 | (x86->opcode[0] & 0xf);

							jump_displacement -= 4;
							memcpy(bytes+2, &jump_displacement, 4);
						}

						// TODO: debug
						/*hprint("JUMP at %#08lx (previously at %#08lx) MUST BE SUBSTITUTED (offset= %d):\n", insn->new_addr, insn->orig_addr, jump_displacement);
						hdump(1, "FROM", insn->i.x86.insn, insn->size);
						hdump(1, "TO", bytes, sizeof(bytes));*/
						substitute_instruction_with(insn, bytes, sizeof(bytes), &insn);

						offset = x86->opcode_size;
						size = x86->insn_size - x86->opcode_size;

						hnotice(5, "Changed into a long jump\n");
					}
				}

				hnotice(5, "It's a long jump, just update the displacement to %#0llx\n", jump_displacement);
				memcpy((x86->insn + offset), &jump_displacement, size);

			// must be taken into account embedded CALL instructions (ie. for local functions)
			// such that theirs offset are generated directly into the code instead of using a relocation
			}

			insn = insn->next;
		}

		foo = foo->next;
	}


	// update all the relocation that reference instructions
	// beyond the one instrumented. (ie. in case of switch tables)
	hnotice(4, "Check relocation symbols\n");

	/*sym = PROGRAM(symbols);
	sec = PROGRAM(sections);
	while(sec) {
		if(sec->type == SECTION_RELOC) {
			rel = sec->payload;

			while(rel) {
				sym = rel->symbol;

				// looks for refrences which applies to .text section
				if(sym && !strcmp(sym->name, ".text")) {

					if(sym->offset > target->new_addr) {
						hnotice(5, "Symbol %d (%s) at offset %#08lx with addend %#0lx ", sym->index, sym->name, sym->position, rel->addend);

						old_offset = rel->addend;
						rel->addend += shift;
						sym->offset = rel->addend;

						hnotice(5, "is shifted to offset %#08lx with addend %#0lx (shift = %+d)\n", sym->position, rel->addend, shift);
					}
				}

				rel = rel->next;
			}
		}

		sec = sec->next;
	}*/
	sym = PROGRAM(symbols);

	printf("\n\nsymbols: ");
	while(sym) {

		printf("%p '%s' -- ", sym, sym->name);

		// Looks for refrences which applies to .text section
		if(!strcmp(sym->name, ".text")) {

			// Update only those relocations beyond the code affected by current instrumentation
			if(sym->relocation.addend > target->new_addr) {
				sym->relocation.addend += shift;

				hnotice(5, "Relocation to symbol %d (%s) at offset %#08lx addend updated %#0lx (%+d)\n",
					sym->index, sym->name, sym->position, sym->relocation.addend, shift);
			}
		}

		sym = sym->next;
	}
	printf("\n");
}


static void insert_insn_at (insn_info *target, insn_info *insn, int flag) {
	function *func;


	// TODO: debug
	/*hprint("ISTRUZIONE: '%s' <%#08lx> -- op_size=%d, disp_off=%d, jump_dest=%d, size=%d\n", x86->mnemonic, x86->addr,
			x86->opcode_size, x86->disp_offset, x86->jump_dest, x86->insn_size);*/

	// then link the new node
	// TODO: check! may fails in the limit cases, probably...
	switch(flag) {
	case INSERT_BEFORE:
		insn->next = target;
		insn->prev = target->prev;

		target->prev->next = insn;
		target->prev = insn;
		break;

	case INSERT_AFTER:
		insn->next = target->next;
		insn->prev = target;

		target->next->prev = insn;
		target->next = insn;
		break;

	default:
		herror(true, "Unrecognized insert rule's flag parameter!\n");
	}

	// Update instruction references
	// since we are adding a new instruction, the shift amount
	// is equal to the instruction's size
	update_instruction_references(NULL, insn, insn->size);

	//func = get_function(target);
	//hnotice(4, "Inserted a new instruction node %s the instruction at offset <%#08lx> in function '%s'\n", flag == INSERT_AFTER ? "after" : "before", target->new_addr, func->symbol->name);
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
static void substitute_insn_with(insn_info *target, insn_info *insn) {
	function *func;
	int insn_size;
	int old_size;


	// we have to update all the references
	// why add the opcode size again??
	// delta shift should be the: d = (old size - the new one) [signed, obviously]

	insn->orig_addr = target->orig_addr;
	insn->new_addr = target->new_addr;

	insn->prev = target->prev;
	insn->next = target->next;
	if(target->prev)
		target->prev->next = insn;
	if(target->next)
		target->next->prev = insn;
	free(target);

	update_instruction_references(func, insn, (insn->size - old_size));

	//func = get_function(target);
	//hnotice(4, "Substituting instruction at address <%#08lx> in function '%s'\n", target->orig_addr, func->symbol->name);
}


int insert_instructions_at (insn_info *target, char *binary, size_t size, int flag, insn_info **insn) {
	unsigned long int pos;
	int count;

	hnotice(4, "Inserting instrucions from raw binary code (%d bytes) %s the instruction at %#08lx\n",
		size, INSERT_BEFORE ? "before" : "after", target->new_addr);
	hdump(5, "Binary", binary, size);

	// Pointer 'binary' may contains more than one instruction
	// in this case, the behavior is to convert the whole binary
	// and adds the relative instruction to the current representation
	pos = 0, count = 0;
	while(pos < size) {
		// Interprets the binary bytes and packs the next instruction
		parse_instruction_bytes(binary, &pos, insn);

		// Adds the newly creaed instruction descriptor to the
		// internal binary representation
		insert_insn_at(target, *insn, flag);

		count++;
	}

	hnotice(4, "Inserted %d instruction %s the target <%#08lx>\n", count, INSERT_BEFORE ? "before" : "after", target->new_addr);

	return count;
}


int substitute_instruction_with (insn_info *target, char *binary, size_t size, insn_info **insn) {
	insn_info *substituted;
	unsigned long int pos;
	int count;


	hnotice(4, "Substituting target instruction at %#08lx with binary code\n", target->new_addr);
	hdump(5, "Binary code", binary, size);

	// Pointer 'binary' may contains more than one instruction
	// in this case, the behavior is to convert the whole binary
	// and adds the relative instruction to the current representation

	// First instruction met will substitute the current target
	// whereas the following have to be inserted just after it
	parse_instruction_bytes(binary, &pos, insn);
	substitute_insn_with(target, *insn);
	substituted = *insn;
	pos = 0, count = 1;

	while(pos < size) {
		// Interprets the binary bytes and packs the next instruction
		parse_instruction_bytes(binary, &pos, insn);

		// Adds the newly creaed instruction descriptor to the
		// internal binary representation
		insert_insn_at(substituted, *insn, INSERT_AFTER);

		count++;
	}

	hnotice(4, "Target instruction subsituted with %d instructions\n", count);

	return count;
}


// TODO: da rivedere se utile da implementare
/**
 * Given a symbol, this function will create a new CALL instruction
 * and returns it. The instruction can be passed to the insertion
 * function to add it to the remainder of the code.
 *
 * @param target The pointer to the pivot instruction descriptor
 * @param function Name of the function to be called
 * @param where Integer constant which defines where to add the call wrt target
 */
void add_call_instruction (insn_info *target, char *function, int where) {
	insn_info *insn;
	symbol *sym;
	char *call;
	unsigned long int pos;

	// TODO: da spostare in un file a parte per x86!
	call = (char *) malloc(5);
	bzero(call, 5);
	call[0] = 0xe8;
	pos = 0;

	// Checks and creates the symbol name
	sym = create_symbol_node(function, SYMBOL_UNDEF, SYMBOL_GLOBAL, 0);

	// Create the CALL node
	parse_instruction_bytes(call, &pos, &insn);

	// Adds the instruction to the binary representation
	// WRANING! We MUST add the instruction BEFORE to create
	// the new rela node, otherwise the instruction's address
	// will not be coherent anymore once at the amitting step
	insert_insn_at(target, insn, where);

	// Once the instruction has been inserted into the binary representation
	// and each address and reference have been properly updated,
	// create a new RELA entry
	instruction_rela_node(sym, insn, RELOCATE_RELATIVE_32);
}
