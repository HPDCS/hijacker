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
                     unsigned char *bytes, size_t size, sec_t *section) {
	sym_t *symbol, *pivot;

	static unsigned int id = 0;

	// TODO: Check symbol size?

	if (!name) {
		hinternal();
	}
	else if (type != SYMBOL_SECTION && !section) {
		// A non-section symbol must always have a parent section.
		// NOTE: The correct way to use this function is therefore
		// to create a section symbol, then the section, then any
		// non-section symbol contained in this section.
		// TODO: Check other cases (e.g. COMMON, ABS, etc.)
		hinternal();
	}

	// Populate the new symbol descriptor
	symbol = hcalloc(sizeof(sym_t));

	symbol->id = ++id;
	symbol->name = str_copy(name);
	symbol->type = type;
	symbol->flags = flags;
	symbol->bytes = bytes;
	symbol->size = size;
	symbol->section = section;

	// FIXME: How to handle non-allocated symbols?
	// Their size should be the size in memory, but a NULL
	// payload because the default value is defined in the
	// OFF standard of choice (e.g., ELF)

	// Insert descriptor in the symbol chain at the right position:
	// if a section symbol, insert it as the last section symbol;
	// else, insert it as the last symbol in the parent section.
	if (!section) {
		pivot = __VERSION__(sections).last->symbol;
		symbol->node = list_insert(&__VERSION__(symbols), symbol, pivot, INSERT_AFTER);
	}
	else {
		pivot = section->has.symbols.last;
		symbol->node = list_insert(&__VERSION__(symbols), symbol, pivot, INSERT_AFTER);

		range_insert(&section->has.symbols, pivot, symbol->node, INSERT_AFTER);

		symbol->offset = section->symbol->size;
		section->symbol->size += symbol->size;
	}

	return symbol;
}


void *symbol_remove(sym_t *symbol) {
	sec_t *section;

	if (!symbol) {
		hinternal();
	}

	// Remove descriptor from the section chain
	list_remove(&__VERSION__(symbols), symbol->node);

	section = symbol->section;

	if (section) {
		range_remove(&section->has.symbols, symbol);

		section->symbol->size -= symbol->size;
		// TODO: Possibly shift offsets of other symbols in the section
	}

	// TODO: Remove all relocations referring to this symbol
	// TODO: Remove function/section represented by this symbol

	// Deallocate section descriptor, which is no longer valid
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

