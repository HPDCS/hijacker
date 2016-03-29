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
* @file reloc.c
* @brief Module to handle relocations in the IBR
* @author Simone Economo
*/


rel_t *reloc_insert(unsigned long type, sec_t *section, addr_t offset,
                    sym_t *symbol, off_t addend) {
	rel_t *reloc;

	if (section == NULL || symbol == NULL) {
		hinternal();
	}

	// Make room for a new relocation descriptor
	reloc = hcalloc(sizeof(rel_t));

	// Fill relocation descriptor fields
	reloc->type = type;
	reloc->in.section = section;
	reloc->in.offset = offset;
	reloc->to.symbol = symbol;
	reloc->to.addend = addend;

	// Insert the descriptor into the relocation chain
	reloc->node = list_push_last(&__VERSION__(relocs), reloc);

	return reloc;
}


rel_t *reloc_isn_to_sym(unsigned long type, isn_t *instr,
                        sym_t *symbol, off_t addend) {
	rel_t *reloc;
	sec_t *section;

	if (!instr) {
		hinternal();
	}

	// TODO: To implement
	section = section_find_frominstr(instr);

	// Create generic relocation and link it to the instruction
	reloc = reloc_insert(type, section, instr->offset, symbol, addend);
	reloc->in.instr = instr;

	// NOTE: The addend is correctly set in `reloc_insert` by
	// passing the appropriate type

	// Add relocation to the list of relocations owned by the passed
	// instruction
	list_push_last(&instr->rel.source, reloc);

	return reloc;
}


rel_t *reloc_sec_to_isn(unsigned long type, sec_t *section, addr_t offset,
                        isn_t *instr) {
	rel_t *reloc;
	sec_t *symbol_sec;

	if (!instr) {
		hinternal();
	}

	// TODO: To implement
	symbol_sec = section_find_frominstr(instr);

	// Create generic relocation and link it to the instruction
	reloc = reloc_insert(type, section, offset, symbol_sec->symbol, addend);
	reloc->to.instr = instr;

	// Add relocation to the list of relocations which refer to the passed
	// instruction
	list_push_last(&instr->rel.dest, reloc);

	return reloc;
}


rel_t *reloc_remove(rel_t *reloc) {
	isn_t *instr;

	list_node_t *node;

	if (!reloc) {
		// FIXME: In principle, we could just return from the function
		hinternal();
	}

	// Remove the descriptor from the relocation chain
	list_remove(&__VERSION__(relocs), reloc->node);

	// Remove the node stored in the instruction's local list
	// of source relocations
	if ((instr = reloc->in.instr)) {
		node = list_find(instr->rel.source, reloc);

		if (!node) {
			hinternal();
		}

		list_remove(instr->rel.source, node);
	}

	// Remove the node stored in the instruction's local list
	// of destination relocations
	if ((instr = reloc->to.instr)) {
		node = list_find(instr->rel.dest, reloc);

		if (!node) {
			hinternal();
		}

		list_remove(instr->rel.dest, node);
	}

	// TODO: Remove the instruction which uses the relocation

	// Deallocate the descriptor, which is no longer valid
	free(reloc);
}


rel_t *reloc_find_bysymbol(sym_t *symbol, sec_t *section) {
	static list_node_t *current;
	static sym_t *to;
	static sec_t *in;

	list_node_t *node;
	rel_t *reloc;

	if (!symbol || !section) {
		hinternal();
	}

	if (symbol != to || section != in) {
		symbol = to;
		section = in;
		current = list_first(&section->relocs);
	}

	while (current) {
		reloc = current->elem;

		if (reloc->to.symbol == to) {
			return reloc;
		}

		current = current->next;
	}

	return NULL;
}

