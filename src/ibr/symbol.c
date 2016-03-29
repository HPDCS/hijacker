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
* @file symbol.c
* @brief Module to handle symbols in the IBR
* @author Simone Economo
*/

#include <string.h>

#include <hijacker.h>
#include <prints.h>
#include <ibr.h>

#include <elf/parse-elf.h>


sym_t *symbol_insert(const char *name, unsigned long type, unsigned long flags,
                     sec_t *section, unsigned char *bytes) {
	sym_t *symbol;

	static unsigned int id = 0;

	if (!name || !section) {
		hinternal();
	}

	// TODO: What to do with symbols that belong to non-defined sections?
	// TODO: Set offset and update section symbol size

	// Make room for a new symbol descriptor
	symbol = hcalloc(sizeof(sym_t));

	// Fill symbol descriptor fields
	symbol->id = ++id;
	symbol->name = str_copy(name);
	symbol->type = type;
	symbol->flags = flags;
	symbol->section = section;

	// TODO: If symbol is internally-defined, payload must be non-NULL
	symbol->bytes = bytes;

	// Insert the descriptor into the symbol chain
	symbol->node = list_push_last(&__VERSION__(symbols), symbol);

	return symbol;
}


void *symbol_remove(sym_t *symbol) {
	if (!symbol) {
		hinternal();
	}

	// TODO: Update section symbol size
	// TODO: Possibly shift offsets of other symbols!

	// Remove the descriptor from the symbol chain
	list_remove(&__VERSION__(symbols), symbol->node);

	// TODO: Remove all relocations referring to this symbol
	// TODO: Remove function/section represented by this symbol

	// Deallocate the descriptor, which is no longer valid
	free(symbol);
}


sym_t *symbol_find_byname(const char *name) {
	list_node_t *node;
	sym_t *symbol;

	// TODO: Multiple symbols with the same name can exist!

	if (!name) {
		hinternal();
	}

	list_for_each(&__VERSION__(symbols), node) {
		symbol = node->elem;

		if (str_equal(symbol->name, name)) {
			return symbol;
		}
	}

	return NULL;
}


sym_t *symbol_find_byaddr(addr_t address, sec_t *section) {
	sym_t *symbol, *prev;

	if (!section || section->type != SECTION_RAW) {
		hinternal();
	}

	list_for_each(&__VERSION__(symbols), node) {
		symbol = node->elem;

		if (symbol->offset > address) {
			return prev;
		}

		prev = symbol;
	}

	return NULL;
}

