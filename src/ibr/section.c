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


sec_t *section_insert(unsigned long type, unsigned long flags, sym_t *symbol) {
	sec_t *section;

	static unsigned int id = 0;

	if (!symbol) {
		hinternal();
	}

	// Populate the new section descriptor
	section = hcalloc(sizeof(sec_t));

	section->id = ++id;
	section->type = type;
	section->flags = flags;
	section->symbol = symbol;

	// Link section descriptor with section symbol descriptor in IBR
	symbol->isa.section = section;

	// Insert descriptor in the section chain
	section->node = list_push_last(&__VERSION__(sections), section);

	return section;
}


void *section_remove(sec_t *section) {
	if (!section) {
		hinternal();
	}

	// Remove descriptor from the section chain
	list_remove(&__VERSION__(sections), section->node);

	// TODO: Remove section symbol
	// TODO: Remove all symbols contained in this section
	// TODO: Remove all functions contained in this section

	// Deallocate section descriptor, which is no longer valid
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


static list_range_t section_code_parse(sec_t *section) {
	isn_range_t instructions;

	list_node_t *sym_node, *instr_node, *instr_node_last, *instr_node_first;

	fun_t *function;
	isn_t *instr, *first, *last;
	sym_t *symbol;

	// FIXME: Doesn't work with overlapping functions!

	// TODO: Link jump instructions!
	// TODO: Parse relocations!

	// All the instructions contained in the section are parsed
	// at once thanks to our awesome API for instructions insertion!
	instructions = instr_parse(section->symbol->bytes, INSTR_RAWBYTES);

	if (!range_valid(instructions)) {
		return;
	}

	// We start a synchronous traversal of function symbols in
	// this section and previously-parsed instructions, in order
	// to create a range of functions that this section contains.
	instr_node = instr_node_first = instructions.first;

	list_for_each(&__VERSION(symbols)__, sym_node) {
		// NOTE: Symbols are inserted in the order of their offsets
		// This way, we can maintain a single function pointer which
		// is guaranteed to contain the next breakpoint.
		symbol = sym_node->elem;

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
			// becomes the first instruction of the function.
			while (instr_node != instructions.last->next) {

				if (instr_node->elem->offset == symbol->offset) {
					// FIXME: We check for equality, but strange things
					// could happen with handwritten Assembly code (e.g.,
					// obfuscated code), so this need to be double-checked.
					break;
				}

				instr_node_last = instr_node;
				instr_node = instr_node->next;
			}

			if (instr_node == instructions.last->next) {
				// An instruction which is located at the symbol offset
				// must be found, otherwise we cannot proceed
				hinternal();
			}

			// Create the new function and update the previous
			// instruction pointer
			function = function_insert(NULL,
				range(instr_node_first, instr_node_last),
				section, symbol);

			// The next first instruction is the one that comes
			// after the current last
			instr_node_first = instr_node;
		}
	}

	return range(first, function);
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
