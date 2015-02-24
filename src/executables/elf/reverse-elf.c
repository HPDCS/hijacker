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
* @file reverse-elf.c
* @brief Code needed by the 'trampoline' module to support reverse code generation.
* @author Davide Cingolani
* @date July 24, 2014
*/

#include <hijacker.h>
#include <prints.h>
#include <instruction.h>
#include <trampoline.h>

#include "reverse-elf.h"
#include "handle-elf.h"


static void push_insn_entry (insn_info *target, insn_entry *entry) {
	// choose which subfunction use to fill the structure properly
	// according to the executable file type
	switch (PROGRAM(insn_set)) {
		case X86_INSN:
			push_x86_insn_entry (target, entry);
		break;
	}

	hnotice(4, "Pushed 'insn_entry' strucure into the stack (%d bytes)\n", sizeof(insn_entry));
}


static void get_memwrite_info (insn_info *insn, insn_entry *entry) {
	// choose which subfunction use to fill the structure properly
	// according to the executable file type
	switch (PROGRAM(insn_set)) {
		case X86_INSN:
			get_x86_memwrite_info (insn, entry);
		break;

		default:
			entry = NULL;
	}

	hnotice(4, "Instruction entry for trampoline module created:\n");
	hnotice(4, "MOV %d bytes value to <%#08lx>\n", entry->size,
		entry->base + entry->idx * entry->scala + entry->offset);
}


static void add_call_trampoline (insn_info *target, symbol *reference) {
	insn_info *call;

	switch (PROGRAM(insn_set)) {
		case X86_INSN:
			call = (insn_info *) insert_x86_call_instruction (target);
		break;
	}

	hnotice(4, "Creating the RELA reference to the trampoline...\n");
	instruction_rela_node(reference, call, RELOCATE_RELATIVE_64);
}



void trampoline_prepare (insn_info *target, char *func) {
	insn_entry entry;
	symbol *sym;

	// Retrieve information to fill the structure
	hnotice(4, "Retrieve meta-info about target MOV instruction...\n");
	get_memwrite_info(target, &entry);

	// Adds the pointer to the function that the trampoline module has to call at runtime
	// The idea is to generalize the calling method, the aforementioned
	// symbol will be properly relocated to whichever function the user has
	// specified in the rules files in the AddCall tag's 'function' field
	hnotice(4, "Push function pointer to the trampoline structure <%#08lx>\n", func);
	sym = create_symbol_node(func, SYMBOL_UNDEF, SYMBOL_GLOBAL, 0);

	// Once the structure has been created, it is possbile
	// to generate the push instructions and add them to the code
	hnotice(4, "Push trampoline structure into stack before the target MOV...\n");
	push_insn_entry(target, &entry);

	// Now, we have either the function symbol to be called and the stack filled up;
	// the only thing that remains to do is to adds a relocation entry from the last
	// long-word of the pushed entry towards the new function symbol.
	// Note that 'target' actually is the 2nd MOV instruction being instrumented, therefore
	// in order to make the correct relocation we have to look for its predecessor (twice)
	// which (should) be the last MOV that should pushes the calling address on the stack
	instruction_rela_node(sym, target->prev->prev, RELOCATE_ABSOLUTE_64);
}


inline void prepare_trampoline_call (insn_info *target, symbol *trampoline) {
	insn_entry entry;

	// retrieve information to fill the structure
	hnotice(4, "Retrieve meta-info about target MOV instruction...\n");
	get_memwrite_info(target, &entry);

	// once the structure has been created, it is possbile
	// to generate the push instructions and add them to the code
	hnotice(4, "Push trampoline structure into stack before the target MOV...\n");
	push_insn_entry(target, &entry);

	// add the call to the trampoline
	hnotice(4, "Add CALL instruction to the montor...\n");
	add_call_trampoline(target, trampoline);

	hnotice(2, "MOV instruction at <%#08lx> moved to <%#08lx>\n", target->orig_addr, target->new_addr);
	hnotice(2, "trampoline instrumented for MOV instruction at <%#08lx>\n\n", target->new_addr);
}
