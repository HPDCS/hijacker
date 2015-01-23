#include <stdlib.h>
#include <string.h>

#include <hijacker.h>
#include <prints.h>
#include <instruction.h>

#include <elf/handle-elf.h>

#include "insert_insn.h"


/**
 * Updates all the instruction addresses and references, either jump destinations and relocation entries.
 * Starting from the target instruction, that is the one newly created or subsituted, the function will
 * perform an update of all the addresses and refereces of the following instructions. Address is shifted
 * up by the parameter 'shift'; this is an unsigned value. To properly work, it is needed that the newly
 * created instruction node has the right address, namely the one that should have in the final result.
 * Then, this function will eventually update the address of the other instructions, but the target's one
 * must be correctly set, already.
 *
 * @param func Function description to which the target instruction belongs
 * @param target Description of the target instruction (either the one substituted or the
 * newly created)
 * @param shift Number (signed) of bytes by which shift all the references
 */
static void update_instruction_references(function *func, insn_info *target, int shift) {
	insn_info *insn;
	insn_info *jumpto;
	insn_info_x86 *x86;
	symbol *sym;
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
	func->symbol->size += shift;

	// now, we have to update the addresses of all the remaining instructions in the function
	// ATTENZIONE! Non è corretto fare questo perché gli offset delle istruzioni sono a partire
	// dall'inizio della sezione .text quindi sarebbe necessario aggiornare TUTTI i riferimenti
	// e non solo quelli relativi alla funzione in questione (... a meno che non si cambi la
	// logica degli offset nel descrittore di istruzione a rappresentare lo spiazzamento
	// relativo all'interno della funzione di appartenenza, ma non so quali altri problemi comporta)
	hnotice(4, "Recalculate instructions' addresses\n");
	hnotice(5, "Updating instructions in function '%s'\n", func->name);
	
	insn = target->next;
	while(insn) {
		old_offset = insn->new_addr;
		insn->i.x86.addr = insn->new_addr += shift;

		hnotice(6, "Instruction '%s' at offset <%#08lx> shifted to new address <%#08lx>\n", insn->i.x86.mnemonic, old_offset,
				insn->new_addr);

		insn = insn->next;
	}

	foo = func->next;
	while(foo) {
		hnotice(5, "Updating instructions in function '%s'\n", foo->name);

		insn = foo->insn;
		while(insn) {
			old_offset = insn->new_addr;
			insn->i.x86.addr = insn->new_addr += shift;

			hnotice(6, "Instruction '%s' at offset <%#08lx> shifted to new address <%#08lx>\n", insn->i.x86.mnemonic, old_offset,
				insn->new_addr);

			insn = insn->next;
		}

		foo = foo->next;
	}

	// update jump references, if any, from this function to end of code
	hnotice(4, "Check jump displacements\n");

	//foo = PROGRAM(code);
	foo = func;
	while(foo) {

		insn = foo->insn;
		while(insn){
			
			if(IS_JUMP(insn)) {
				jumpto = (insn_info *) insn->reference;
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

						substitute_instruction_with(func, insn, bytes, sizeof(bytes));

						offset = x86->opcode_size;
						size = x86->insn_size - x86->opcode_size;

						hnotice(5, "Changed into a long jump\n");
					}
				}

				hnotice(5, "It's a long jump, just update the displacement to %#0lx\n", jump_displacement);
				memcpy((x86->insn + offset), &jump_displacement, size);

			// must be taken into account embedded CALL instructions (ie. for local functions)
			// such that theirs offset are generated directly into the code instead of using a relocation
			} /*else if(IS_CALL(insn) && insn->reference) {
				jumpto = insn->reference;
				jump_displacement = jumpto->new_addr - (insn->new_addr + insn->size);
				
				hnotice(5, "Local function call instruction at <%#08lx> (originally <%#08lx>) +%#0lx points to address %#08lx (originally %#08lx)\n",
					insn->new_addr, insn->orig_addr, jump_displacement, jumpto->new_addr, jumpto->orig_addr);

				memcpy(x86->insn, &jump_displacement, 4);
				//hprint("SHOULD COPY %d in CALL at %#08lx (%d bytes)\n", jump_displacement, insn->new_addr, (insn->size - insn->opcode_size));

				hnotice(5, "Updated to address %#08lx\n", jump_displacement);
			}*/

			insn = insn->next;
		}

		foo = foo->next;
	}


	// update all the relocation that reference instructions
	// beyond the one instrumented. (ie. in case of switch tables)
	hnotice(4, "Check relocation symbols\n");
	
	sym = PROGRAM(symbols);
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
	}
}


insn_info * parse_instruction_bytes (char *bytes, size_t size) {
	insn_info *insn;
	insn_info_x86 x86;
	unsigned long pos;
	int flags;

	// creates the new instruction node
	insn = (insn_info *) malloc(sizeof(insn_info));
	bzero(insn, sizeof(insn_info));
	bzero(&x86, sizeof(insn_info_x86));

	memcpy(&x86.insn, bytes, size);
	insn->i.x86 = x86;

	// parse the input bytes to correctly understand which instruction
	// they represents
	pos = flags = 0;
	flags |= ELF(is64) ? DATA_64 : DATA_32;

	// TODO: to be revised, x86 code must reside in proper files!
	x86_disassemble_instruction(bytes, &pos, &x86, flags);

	insn->opcode_size = x86.opcode_size;
	insn->size = x86.insn_size;

	// TODO: debug
	//hprint("INSTRUCTION PARSED: '%s' <%#08lx> -- size=%d, disp_off=%d, jump_dest=%d\n", x86.mnemonic, x86.addr,
	//		x86.opcode_size, x86.disp_offset, x86.jump_dest);
	
	return insn;
}


// TODO: what if the 'insert_instruction_at' function would take as parameter an instruction
// descriptor instead of a raw byte array?
// Doing so, a new function is needed to create the instruction descriptor from the byte array

// insn_info * insert_instruction_at (function *func, insn_info *offset, insn_info *insn, int flag);
insn_info * insert_instruction_at(function *func, insn_info *target, char *bytes, size_t num_bytes, int flag) {

	insn_info *insn;
	insn_info *jump;
	insn_info_x86 *x86;
	symbol *sym;
	section *sec;
	reloc *rel;
	int old_offset;
	int flags;
	unsigned long pos;

	hnotice(4, "Inserting a new instruction node %s the instruction at offset <%#08lx> in function '%s'\n",
			flag == INSERT_AFTER ? "after" : "before", target->new_addr, func->symbol->name);
	hdump(5, "Instruction bytes", bytes, num_bytes);
	
	// TODO: to separate form other instruction sets?

	// creates the new instruction node
	insn = (insn_info *) malloc(sizeof(insn_info));
	bzero(insn, sizeof(insn_info));

	x86 = &(insn->i.x86);
	bzero(x86, sizeof(insn_info_x86));
	memcpy(x86->insn, bytes, num_bytes);

	// parse the input bytes to correctly understand which instruction
	// they represents
	pos = flags = 0;
	flags |= ELF(is64) ? DATA_64 : DATA_32;		// set data size flags
	flags |= ELF(is64) ? ADDR_64 : ADDR_32;		// set address size flags

	x86_disassemble_instruction(bytes, &pos, x86, flags);

	x86->addr = insn->orig_addr = insn->new_addr = target->new_addr;
	insn->opcode_size = x86->opcode_size;
	insn->size = x86->insn_size;

	// TODO: debug
	/*hprint("ISTRUZIONE: '%s' <%#08lx> -- op_size=%d, disp_off=%d, jump_dest=%d, size=%d\n", x86->mnemonic, x86->addr,
			x86->opcode_size, x86->disp_offset, x86->jump_dest, x86->insn_size);
	*/

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
		herror(true, "Unrecognized rule's flag parameter!\n");
	}

	// update instruction references
	update_instruction_references(func, insn, num_bytes);

	return insn;
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
 * @param func Function descriptor to which target instruction belongs to.
 * @param target Target instruction descriptor pointer.
 * @param bytes Pointer to the opcode that will be substituted to the target instruction's one
 * @param num_bytes Size of the bytes provided.
 */
void substitute_instruction_with(function *func, insn_info *target, char *bytes, size_t num_bytes) {

	insn_info_x86 *x86;
	int insn_size;
	int old_size;
	int flags;
	unsigned long pos = 0;

	hnotice(4, "Substituting instruction at address <%#08lx> in function '%s'\n", target->orig_addr, func->symbol->name);
	hdump(5, "Instruction bytes", bytes, num_bytes);

	x86 = &(target->i.x86);

	// copy the new insn opcode to the target instruction
	bzero(x86->insn, sizeof(x86->insn));
	//memcpy(x86->insn, bytes, num_bytes);

	// updates the instruction size
	old_size = target->size;
	//x86->insn_size = num_bytes;
	//target->size = num_bytes;

	// TODO: needed the insn_info descriptor instead of the simple char *bytes
	// would work calling the x86_disassemble_instruction function?
	flags = 0;
	flags |= ELF(is64) ? DATA_64 : DATA_32;		// set data size flags
	flags |= ELF(is64) ? ADDR_64 : ADDR_32;		// set address size flags

	// TODO: to be refined, x86 code must reside in proper files!
	x86_disassemble_instruction(bytes, &pos, x86, flags);

	target->opcode_size = x86->opcode_size;
	target->size = x86->insn_size;

	/*hprint("INSN SOSTITUITA: (%s) opcode_size= %d, insn_size= %d, jump_dest= %#0x, disp_off= %#0x\n",
			x86->mnemonic, x86->opcode_size, x86->insn_size, x86->jump_dest, x86->disp_offset);*/

	// we have to update all the references
	// why add the opcode size again??
	// delta shift should be the: d = (old size - the new one) [signed, obviously]
	//update_instruction_references(func, target, (num_bytes - old_size + target->opcode_size));
	update_instruction_references(func, target, (target->size - old_size));
}

// TODO: da rivedere se utile da implementare
insn_info * add_call_instruction (symbol *sym) {
	insn_info *call;
	char *bytes;
	int size;

	size = 5;
	bytes = (char *) malloc(size);
	bzero(bytes, size);

	bytes[0] = 0xe8;

	// create the CALL node
	call = parse_instruction_bytes(bytes, size);

	// create a new RELA entry
	create_rela_node(sym, call);
}
