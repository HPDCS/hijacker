/*
 * reverse-elf.c
 *
 * Here all the function needed by the 'monitor' module to support the
 * reverse code generation.
 *
 *  Created on: 24/lug/2014
 *      Author: davide
 */

#include <hijacker.h>
#include <prints.h>
#include <instruction.h>
#include <monitor.h>

#include "reverse-elf.h"


static void push_insn_entry (function *func, insn_info *target, insn_entry *entry) {
	// choose which subfunction use to fill the structure properly
	// according to the executable file type
	switch (PROGRAM(insn_set)) {
		case X86_INSN:
			push_x86_insn_entry (func, target, entry);
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

	hnotice(4, "Instruction entry for monitor module created:\n");
	hnotice(4, "MOV %d bytes value to <%#08lx>\n", entry->size,
		entry->base + entry->idx * entry->scala + entry->offset);
}


static void add_call_monitor (function *func, insn_info *target, symbol *reference) {
	insn_info *call;

	switch (PROGRAM(insn_set)) {
		case X86_INSN:
			call = (insn_info *) insert_x86_call_instruction (func, target, reference);
		break;
	}

	hnotice(4, "Creating the RELA reference to the monitor...\n");
	create_rela_node(reference, call);
}


inline void prepare_monitor_call (function *func, insn_info *target, symbol *monitor) {
	insn_entry entry;

	// retrieve information to fill the structure
	hnotice(4, "Retrieve meta-info about target MOV instruction...\n");
	get_memwrite_info(target, &entry);

	// once the structure has been created, it is possbile
	// to generate the push instructions and add them to the code
	hnotice(4, "Push monitor structure into stack before the target MOV...\n");
	push_insn_entry(func, target, &entry);

	// add the call to the monitor
	hnotice(4, "Add CALL instruction to the montor...\n");
	add_call_monitor(func, target, monitor);

	hnotice(2, "MOV instruction at <%#08lx> moved to <%#08lx>\n", target->orig_addr, target->new_addr);
	hnotice(2, "Monitor instrumented for MOV instruction at <%#08lx>\n\n", target->new_addr);
}
