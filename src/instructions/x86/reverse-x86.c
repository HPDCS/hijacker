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
* @file reverse-x86.c
* @brief Generation of a reverse x86 instruction
* @author Davide Cingolani
* @date July 24, 2014
*/

#include <string.h>

#include <hijacker.h>
#include <prints.h>

#include <executable.h>
#include <instruction.h>
#include <trampoline.h>
#include <insert_insn.h>

#include "x86.h"
#include "reverse-x86.h"


void get_x86_memwrite_info (insn_info *instr, insn_entry *entry) {
	insn_info_x86 *x86;

	// from the instruction descriptor get the x86 instrucion one
	x86 = &(instr->i.x86);
	bzero(entry, sizeof(insn_entry));

	// fill the structure
	entry->size = x86->span;
	entry->offset = x86->disp;
	entry->flags = x86->flags;
	entry->base = x86->breg;
	entry->idx = x86->ireg;
	entry->scala = x86->scale;
}



void push_x86_insn_entry (insn_info *instr, insn_entry *entry) {
	int size;
	int num;
	int idx;
	int value;

	size = sizeof(insn_entry);	// size of the structure
	num = size / 4;				// number of the mov instructions needed to copy all the struture fields

	// Creates bytes array of the main instructions needed to manage
	// the stack in order to save trampoline's structure
	unsigned char sub[4] = {0x48, 0x83, 0xec, (char) size};
	unsigned char mov[8] = {0xc7, 0x44, 0x24, 0x00, 0x00, 0x00, 0x00, 0x00};

	// add the SUB instruction in order to create a sufficent stack window for the structure
	insert_instructions_at(instr, sub, sizeof(sub), INSERT_BEFORE, &instr);

	// iterates all over the mov needed
	for (idx = 0; idx < num; ++idx) {
		bzero((mov + 3), 5);

		mov[3] = idx * sizeof(int);							// displacement from the new stack pointer
		memcpy(&value, (((char *) entry) + idx * sizeof(int)), sizeof(int));	// retrieve the next chunk of 4 bytes
		memcpy((mov + 4), &value, sizeof(int));				// embed the immediate into the instruction

		// create and add the new instruction to the rest of code
		insert_instructions_at(instr, mov, sizeof(mov), INSERT_AFTER, &instr);
	}

	/*symbol *sym;
	sym = create_symbol_node("trampoline_function", SYMBOL_UNDEF, SYMBOL_GLOBAL, 0);
	sym = symbol_check_shared(sym);
	sym->position = insn->new_addr + insn->opcode_size;*/

	//entry->pointer = insn->new_addr + insn->opcode_size;
	//TODO: aggiornare il valore di posizione al variare dell'instrumentazione
}


// TODO: uniformare lo standard delle funzioni per il ritorno dei valori
insn_info * insert_x86_call_instruction (insn_info *target) {
	insn_info *call_insn;
	unsigned char call[5] = {0xe8, 0x00, 0x00, 0x00, 0x00};
	unsigned char add[4] = {0x48, 0x83, 0xc4, (char)sizeof(insn_entry)};

	// add the call instruction in the original code to the module
	insert_instructions_at(target, call, sizeof(call), INSERT_BEFORE, &call_insn);

	// in order to align the stack pointer we need to insert an ADD instruction
	// to compensate the SUB used to make room for the structure
	// note: insn, now, points to the last MOV, therefore the complementary ADD has
	// to be inserted after that instruction
	insert_instructions_at(call_insn, add, sizeof(add), INSERT_AFTER, NULL);

	return call_insn;
}
