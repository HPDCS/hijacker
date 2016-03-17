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


const char *rel_type_str[] = {
	"PCREL_32", "PCREL_64", "TLSREL_32", "ABS_32", "ABS_32S", "ABS_64",
};


rel_t *reloc_create(rel_type_t type, sec_t *section, addr_t offset,
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
	first = &VERSION(relocations).first;
	last = &VERSION(relocations).last;

	if (*first == NULL) {
		// Initialize the list
		*first = reloc;
	}
	else if (*first != *last) {
		// Append to the end of the list
		reloc->prev = *last;
		(*last)->next = reloc;
	}

	*last = reloc;

	return reloc;
}


rel_t *reloc_isn_to_sym(rel_type_t type, isn_t *instr,
                        sym_t *symbol, off_t addend) {
	rel_t *reloc;
	sec_t *section;

	if (instr == NULL) {
		hinternal();
	}

	// TODO: To implement
	section = section_find_frominstr(instr);

	// Create generic relocation and link it to the instruction
	reloc = reloc_create(type, section, instr->offset, symbol, addend);
	reloc->in.instr = instr;

	// Add relocation to the list of relocations owned by the passed
	// instruction
	list_push(&instr->rel.source, reloc);

	return reloc;
}



rel_t *reloc_sec_to_isn(rel_type_t type, sec_t *section, addr_t offset,
                        isn_t *instr) {
	rel_t *reloc;
	sec_t *symbol_sec;

	if (instr == NULL) {
		hinternal();
	}

	// TODO: To implement
	symbol_sec = section_find_frominstr(instr);

	// Create generic relocation and link it to the instruction
	reloc = reloc_create(type, section, offset, symbol_sec->symbol, addend);
	reloc->to.instr = instr;

	// Add relocation to the list of relocations which refer to the passed
	// instruction
	list_push(&instr->rel.dest, reloc);

	return reloc;
}
