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
* @file version.c
* @brief Module to handle versions in the IBR
* @author Simone Economo
*/


static __strong_inline__ char *rename(const char *original) {
	return strconcat(original, "_", __VERSION__(name));
}


static __strong_inline__ sec_t *section_clone(sec_t *section, sym_t *symbol) {
	sec_t *clone;

	clone = section_insert(rename(section->name), section->type,
		section->flags, section->payload, symbol);

	return clone;
}


static __strong_inline__ sym_t *symbol_clone(sym_t *symbol) {
	sym_t *clone;

	clone = symbol_insert(rename(symbol->name), symbol->type,
		symbol->flags, symbol->payload);

	return clone;
}


static __strong_inline__ rel_t *reloc_clone(rel_t *reloc, sec_t *section, sym_t *symbol) {
	rel_t *clone;

	clone = reloc_insert(reloc->type, section, reloc->in.offset,
		symbol, reloc->to.addend);

	return clone;
}


static void version_clone(ver_t *version) {
	ver_t *zero, *current;

	list_node_t *sym_node, *reloc_node;

	sym_t *symbol, *cloned_symbol;
	sec_t *section, *cloned_section;
	rel_t *reloc;

	zero = __PROGRAM__(versions)[0];
	current = __PROGRAM__(version);

	// Temporarily switch to new version
	__PROGRAM__(version) = version;

	list_for_each(&zero->symbols, sym_node) {
		symbol = sym_node->elem;

		if (symbol->type == SYMBOL_SECTION) {
			section = symbol->isa.section;

			if (section->type == SECTION_CODE) {
				// If the symbol refers to a section, and this section
				// is a CODE section, it must be cloned since Hijacker's
				// multi-versioning feature preserves the original code.
				cloned_symbol = symbol_clone(symbol);
				cloned_section = section_clone(section, cloned_symbol);

				// We clone all CODE -> * relocations, since they must
				// apply to the cloned CODE section.
				list_for_each(&section->relocs, reloc_node) {
					reloc = reloc_node->elem;

					// TODO: Check that reloc->symbol must *not* be cloned
					reloc_clone(reloc, cloned_section, reloc->to.symbol);
				}

				// We clone all * -> CODE relocations, since they must
				// refer to the cloned CODE section.
				list_for_each(&symbol->relocs, reloc_node) {
					reloc = reloc_node->elem;

					// TODO: Inflate data sections so to accommodate the
					// new relocations!
					reloc_clone(reloc, reloc->to.section, cloned_symbol);
				}
			}

		}

	}

	// Restore previous version
	__PROGRAM__(version) = current;
}


ver_t *version_create(const char *name) {
	ver_t *version;

	if (name == NULL) {
		hinternal();
	}

	// Make room for a new function descriptor
	version = hcalloc(sizeof(ver_t));

	// Fill version descriptor fields
	version->number = PROGRAM(nversions);
	version->name = name;

	// Insert the descriptor into the version array
	__PROGRAM__(versions)[version->number] = version;
	__PROGRAM__(nversions) += 1;

	if (version->number != 0) {
		version_clone(version);
	}

	return version;
}


ver_t *version_switch(unsigned long number) {
	ver_t *version;

	if (number >= MAX_VERSIONS) {
		hinternal();
	}

	// Can be NULL if there's no version with that number
	version = __PROGRAM__(versions)[number];

	if (!version) {
		hinternal();
	}

	__PROGRAM__(version) = version;

	return version;
}
