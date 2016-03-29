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
* @file section.c
* @brief Module to handle sections in the IBR
* @author Simone Economo
*/

#include <string.h>

#include <hijacker.h>
#include <prints.h>
#include <ibr.h>


sec_t *section_insert(const char *name, unsigned long type, unsigned long flags,
                      void *payload, sym_t *symbol) {
	sec_t *section;
	sym_t *symbol;

	static unsigned int id = 0;

	// Make room for a new section descriptor
	section = hcalloc(sizeof(sec_t));

	// Fill section descriptor fields
	section->id = ++id;
	section->type = type;
	section->flags = flags;

	// Insert the descriptor into the section chain
	section->node = list_push_last(&__VERSION__(sections), section);

	// If requested, create a new symbol, too
	if (!symbol) {
		// TODO: Specify symbol flags to insert
		// TODO: Name must be valid
		symbol = symbol_insert(name, SYMBOL_SECTION, 0L, section, payload);
	}

	section->symbol = symbol;
	symbol->isa.section = section;

	// TODO: Set section symbol size

	return section;
}


void *section_remove(sec_t *section) {
	if (!section) {
		hinternal();
	}

	// Remove the descriptor from the section chain
	list_remove(&__VERSION__(sections), section->node);

	// TODO: Remove the symbol representing this section
	// TODO: Remove all symbols contained in this section
	// TODO: Remove all functions contained in this section

	// Deallocate the descriptor, which is no longer valid
	free(section);
}


sec_t *section_find_byname(const char *name) {
	sym_t *symbol;

	symbol = symbol_find_byname(name);

	if (symbol) {
		return symbol->isa.section;
	}

	return NULL;
}


static void section_code_parse(sec_t *section) {
	isn_range_t instructions;

	fun_t *function, *first;
	isn_t *instr, *prev;

	list_node_t *node;
	sym_t *symbol;

	// TODO: Link jump instructions!
	// TODO: Parse relocations!

	// All the instructions contained in the section are parsed
	// at once thanks to our awesome API for instructions insertion!
	instructions = instr_insert(section->symbol->bytes, INSTR_RAWBYTES, NULL, INSERT_BEFORE);

	// We start a synchronous traversal of function symbols in
	// this section and previously-parsed instructions, in order
	// to create a range of functions that this section contains.
	instr = prev = instructions.first;

	list_for_each(&__VERSION(symbols)__, node) {
		// NOTE: Symbols are inserted in the order of their offsets
		// This way, we can maintain a single function pointer which
		// is guaranteed to contain the next breakpoint.
		symbol = node->elem;

		if (symbol->type == SYMBOL_FUNCTION && symbol->section == section) {
			// We apply an iterative region splitting algorithm which
			// creates functions based on instruction breakpoints.
			// Such breakpoints are retrieved by retrieving the
			// instruction located at the current symbol's offset.

			if (function == NULL) {
				// If we've reached the end of the section, but another
				// symbol has been found, then something must have gone
				// horribly wrong...
				hinternal();
			}

			// We keep navigating the instruction range until we find
			// an instruction whose offset matches with the offset of
			// the function symbol. In that case, the instruction
			// becomes the first instruction of the function referred
			// by the symbol.
			while (instr && instr->offset <= symbol->offset) {
				instr = instr->next;
			}

			if (!instr || instr->offset != symbol->offset) {
				// An instruction which matches with the offset criterion
				// must be found, otherwise we cannot proceed
				hinternal();
			}

			// Create the new function and update the previous
			// instruction pointer
			function = function_insert(symbol->name, range(prev, instr));


			prev = instr->next;
		}
	}

	section->has.functions = range(first, function);
}


static void section_data_parse(sec_t *section) {
	// TODO: To implement
}


static void section_debug_parse(sec_t *section) {
	// TODO: Not implemented...eventually will be! :-)
}


void section_parse(sec_t *section) {
	if (!section) {
		hinternal();
	}

	switch (type) {
		case SECTION_RAW:
		case SECTION_TLS:
			section->has.symbols = section_data_parse(section);
			break;

		case SECTION_RELOC:
			section->has.relocs = section_reloc_parse(section);
			break;

		case SECTION_CODE:
			section->has.functions = section_code_parse(section);
			break;

		default:
			hinternal();
	}
}
