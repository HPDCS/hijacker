
/**
 * This file provides functions to manipulate parsed ELF structure.
 */

#include <stdio.h>
#include <string.h>

#include <hijacker.h>
#include <prints.h>

#include <executable.h>
#include <instruction.h>

#include "handle-elf.h"


void create_rela_node (symbol *sym, insn_info *insn) {
	symbol *ref;		// a new relocation entry is a duplicate of the referenced symbol;

	// check if the symbol is already been referenced and returns a duplicate
	ref = symbol_check_shared(sym);
	ref->referenced = 1;
	ref->offset = (long)insn->opcode_size - (long)insn->size;		// consider that: the addend is backward and -(a - b) == (b - a)
	ref->reloc_type = R_X86_64_PC32;								// TODO: must not be statically assigned!

	insn->reference = ref;

	hnotice(3, "New RELA node has been created from symbol '%s' %+d  to the instruction at address <%#08lx>\n",
		sym->name, ref->offset, insn->new_addr);
}


symbol * create_symbol_node (char *name, int type, int bind) {
	symbol *sym;
	symbol *node;

	// create the node
	node = (symbol *) malloc(sizeof(symbol));
	bzero(node, sizeof(symbol));

	node->name = (char *) malloc(strlen(name));
	strcpy(node->name, name);
	node->type = type;
	//node->extra_flags = (ELF(is64) ? ELF64_ST_INFO(bind, 0) : ELF32_ST_INFO(bind, 0));
	node->bind = bind;

	// add to the symbol list
	sym = PROGRAM(symbols);
	while (sym->next) {
		sym = sym->next;
	}
	sym->next = node;

	hnotice(3, "New %s symbol '%s' node of type %d has been created\n",
		sym->bind == STB_LOCAL ? "local" : sym->bind == STB_GLOBAL ?  "global" : "weak", node->name, node->type);

	return node;
}


symbol * symbol_check_shared (symbol *sym) {
	symbol *prev, *curr;

	// Check if the field offset is not empty, in this case the symbol
	// is shared and we must create and link a new copy of to store
	// the new relocation offset.
	if(sym->referenced) {

		hnotice(5, "Multiple reference to '%s', duplicating symbol...\n", sym->name);

		// seek the end of the collision list starting from
		// passed symbol
		prev = curr = sym;
		while(curr->next && curr->next->index == sym->index) {
			prev = curr;
			curr = curr->next;
		}

		// copy the last symbol copy
		symbol *s = (symbol *) malloc(sizeof(symbol));
		memcpy(s, sym, sizeof(symbol));

		// this symbol is marked as a copy
		s->duplicate = 1;

		// update the list
		s->next = prev->next;
		prev->next = s;

		// return the new created duplicate
		return s;
	}

	hnotice(5, "First reference to '%s'\n", sym->name);
	// no duplicates, return the symbol itself
	return sym;
}
