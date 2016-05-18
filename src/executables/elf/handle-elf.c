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
* @file handle-elf.c
* @brief Functions to manipulate already-parsed ELF object files
* @author Davide Cingolani
* @author Simone Economo
*/

#include <stdio.h>
#include <string.h>

#include <hijacker.h>
#include <prints.h>
#include <executable.h>
#include <instruction.h>

#include <elf/parse-elf.h>
#include <elf/handle-elf.h>


static void clone_text_sections(int version, char *suffix) {
	function *func;
	section *sec, *clone;

	char *name;

	// Currently, the only way to associate a function with its
	// CODE section is by knowing the function itself. In other
	// words, there is no way to know from a section the functions
	// it contains.

	// To create as many CODE section duplicates as necessary,
	// we iterate over the function chain in the current version
	// and go up to retrieve each time a CODE section.
	// If the duplicate CODE section has already been created,
	// we continue to the next function in the chain.
	// Otherwise, we duplicate the section.
	// In all cases, we update the function-section link in the
	// IBR appropriately.

	for (func = PROGRAM(v_code)[version]; func; func = func->next) {
		sec = func->symbol->sec;

		if (sec == NULL) {
			hinternal();
		}

		name = calloc(sizeof(char), strlen(sec->name) + strlen(suffix) + 2);
		sprintf(name, "%s.%s", sec->name, suffix);
		clone = find_section_by_name(name, version);

		if (clone == NULL) {
			clone = section_clone(sec, suffix);
			section_append(clone, &PROGRAM(sections)[version]);
		}

		func->symbol->sec = clone;
	}
}


/**
 *
 * Nothing to see here---move along, move along.
 *
 */
static void clone_relocations(int version, char *suffix) {
	function *func;
	insn_info *instr;

	ll_node *rela_node;

	symbol *rela, *clone, *sym;

	char *name;

	for (func = PROGRAM(v_code)[version]; func; func = func->next) {
		for (instr = func->begin_insn; instr; instr = instr->next) {

			// --------------------------------------------------------
			// From CODE to *
			// --------------------------------------------------------

			for (rela_node = instr->parent->reference.first; rela_node;
			     rela_node = rela_node->next) {
				rela = rela_node->elem;

				if (rela->type == SYMBOL_SECTION && rela->sec->type == SECTION_CODE) {
					hinternal();
				}

				else if (rela->type != SYMBOL_FUNCTION) {
					clone = symbol_rela_clone(rela);
				}

				else {
					// If it is a relocation toward a function, we must make
					// sure that the function from the new version is referred,
					// not the original one

					// name = malloc(strlen(rela->name) + strlen(suffix) + 2);
					// bzero(name, sizeof(name));
					// sprintf(name, "%s_%s", rela->name, suffix);
					name = add_suffix(rela->name, "_", suffix);

					// We seek the correct function by its name
					// (this should work, provided that cloning of functions
					// and instructions occurs before cloning relocations)
					sym = find_symbol_by_name(name);

					if (sym == NULL) {
						// TODO: This is a gigantic hack to clone function aliases
						// which is not duplicated by `switch_executable_version`,
						// since there is no concrete function's descriptor associated
						herror(false, "Cannot find symbol '%s'\n", name);

						sym = find_symbol_by_name(rela->name);
						if (sym == NULL) {
							hinternal();
						}

						// It is reasonable that this is a function alias which is not in
						// the function list because it was not be cloned in the clone
						// function list step. Here we create a new symbol on-the-fly, to
						// represent it.
						clone = symbol_create(name, sym->type, sym->bind, sym->sec, sym->size);
						clone->func = sym->func;
						clone->offset = sym->offset;
						sym = clone;
						herror(false, "Created a new function alias '%s'\n", sym->name);
					}

					clone = symbol_rela_clone(sym);
					// We need to copy everything since we're cloning an
					// authentic symbol which has no relocation information
					clone->relocation.type = rela->relocation.type;
					clone->relocation.offset = rela->relocation.offset;
					clone->relocation.addend = rela->relocation.addend;
				}

				// We need to update the section information
				clone->relocation.sec = func->symbol->sec;

				clone->relocation.target_insn = instr;
				ll_push(&instr->reference, clone);
			}

			// --------------------------------------------------------
			// From * to CODE
			// --------------------------------------------------------

			for (rela_node = instr->parent->pointedby.first; rela_node;
			     rela_node = rela_node->next) {
				rela = rela_node->elem;

				if (rela->type == SYMBOL_SECTION && rela->sec->type == SECTION_CODE) {
					// hinternal();
				}

				// We seek the symbol associated to the parent section of
				// the current function
				sym = func->symbol->sec->sym;

				if (sym == NULL) {
					hinternal();
				}

				clone = symbol_rela_clone(sym);
				clone->relocation.type = rela->relocation.type;
				clone->relocation.sec = rela->relocation.sec;
				// WARNING: This offset *must* be updated in `adjust_relocations`!
				// If this is not the case, abandon the ship.
				clone->relocation.offset = rela->relocation.offset;
				clone->relocation.addend = rela->relocation.addend;

				clone->relocation.target_insn = instr;
				ll_push(&instr->pointedby, clone);
			}

		}
	}
}


static void adjust_relocations(symbol *symbols, int version, section *text) {
	symbol *rela, *rela2;
	section *sec;

	for (sec = PROGRAM(sections)[0]; sec; sec = sec->next) {

		if (sec->type == SECTION_CODE || sec->type == SECTION_RELOC) {
			continue;
		}

		// Get all relocations at `sec` to `text`, ordered by offset
		// and picked from the global list of symbols `symbols`
		linked_list relocs = { NULL, NULL };
		find_relocations(symbols, sec, text->sym, &relocs);

		// Consume the ordered list of relocations, in order to respect
		// the offset ordering enforced above
		while(!ll_empty(&relocs)) {
			rela = ll_pop_first(&relocs);

			if (rela->version == 0) {
				// We are asking for relocations toward `text`, which is
				// a section belonging to a version > 0
				hinternal();
			}

			if (rela->relocation.target_insn == NULL) {
				// All relocations towards CODE sections should have the
				// `target_insn` field populated
				hinternal();
			}

			// We parse the list of relocations again, this time seeking all
			// relocations which apply to the requested CODE section.
			// In particular, we need to match a X->CODE relocation
			// with a CODE->X relocation. When this happens, we *MIGHT* have
			// found the beginning of a branch table.
			for (rela2 = symbols; rela2; rela2 = rela2->next) {
				if (rela2->authentic == true || rela2->version != version) {
					continue;
				}

				if (rela2->relocation.sec != text) {
					// We ask for CODE->X relocations
					continue;
				}

				if (rela2->relocation.target_insn == NULL) {
					// All relocations at CODE sections should have the
					// `target_insn` field populated
					hinternal();
				}

				if (rela->relocation.sec == rela2->sec
				    && rela->relocation.offset == rela2->relocation.addend) {
					// Cross-matching sections and cross-matching displacements...
					// ...we might have found the beginning of a branch table

					rela2->relocation.addend = sec->sym->size;

					hnotice(3, "Updated CODE->* relocation in <%s + %llx> to <%s + %x>\n",
						rela2->relocation.sec->name, rela2->relocation.offset,
							rela2->name, rela2->relocation.addend);

					break;
				}
			}

			// The offset is updated to the current size of the section,
			// the section size is increased by the size of a relocation
			// entry (which is reasonably equal to 8 bytes...)
			rela->relocation.offset = sec->sym->size;
			// FIXME: Is it safe to suppose that relocations are always 8 bytes long?
			sec->sym->size += sizeof(char *);

			hnotice(3, "Updated *->CODE relocation in <%s + %llx> to <%s + %x>\n",
				rela->relocation.sec->name, rela->relocation.offset,
					rela->name, rela->relocation.addend);
		}
	}
}


int switch_executable_version(int version) {
	function *functions, *func;
	section *texts, *text;

	char *suffix;

	if (version >= MAX_VERSIONS) {
		hinternal();
	}

	// Updates the current working version of the binary representation.
	// NOTE: We must perform this assignment now because all *_clone
	// functions rely on the increased version number.
	// NOTE: I believe it is better not to do that here
	PROGRAM(version) = version;

	// Checks whether the version is already present in the list
	// otherwise it creates a new one by cloning code and relocations,
	// as well as inflating data sections whenever appropriate...
	// (symbols are not copied since they are shared among versions)

	if(!PROGRAM(v_code)[version]) {
		hnotice(3, "Version not present, cloning the binary representation...\n");

		suffix = (char *) (config.rules[version]->suffix);

		// Clones the whole code (function symbols included) from the plain version
		// to the new one, by appending the user-defined suffix to each name.
		// Once cloned, instructions are no more linked together in the call/jump graph;
		// this task belongs to the parsing stage, nevertheless/ we have to re-execute it
		// in order to realign the representation's semantics.
		PROGRAM(v_code)[version] = clone_function_list(PROGRAM(v_code)[0], suffix);

		// Duplicates all sections containing code and updates the section pointer
		// in the respective function symbols, so that the new functions (which
		// were cloned previously) are correctly associated with the new text section.
		clone_text_sections(version, suffix);

		// We now clone all relocations at or to a cloned text so that we can later
		// adjust them if needed. This is a quite naive copy of relocations which
		// only takes care of adjusting the `relocation.sec` field so as to make
		// it point to the cloned text section.
		clone_relocations(version, suffix);

		// For each text section T in the new version, we adjust relocations
		// from X->T in order to create room for new data in X. This should
		// hopefully covers cases such as branch tables and other pointers.
		for (text = PROGRAM(sections)[version]; text; text = text->next) {
			adjust_relocations(PROGRAM(symbols), version, text);
		}

		// Re-linking jump instructions
		link_jump_instructions();

		// Re-creating a CFG
		PROGRAM(blocks)[version] = block_graph_create();

		// Update the executable versions array
		PROGRAM(code) = PROGRAM(v_code)[version];

		// The overall number of handled versions has to be increased
		PROGRAM(versions)++;

		hnotice(4, "Version %d of the executable's binary representation created\n", version);
	}

	hnotice(3, "Switched to version %d\n\n", version);

	return PROGRAM(version);
}
