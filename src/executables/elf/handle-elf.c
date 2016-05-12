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

	char name[256];

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

		bzero(name, sizeof(name));
		strcpy(name, sec->name);
		strcat(name, ".");
		strcat(name, suffix);

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
 *
 */
static void clone_relocations(int version, char *suffix) {
	function *func;
	insn_info *instr;

	ll_node *rela_node;

	symbol *rela, *clone, *sym;

	unsigned char name[256];

	for (func = PROGRAM(v_code)[version]; func; func = func->next) {
		for (instr = func->begin_insn; instr; instr = instr->next) {

			// --------------------------------------------------------
			// From CODE to *
			// --------------------------------------------------------

			for (rela_node = instr->parent->reference.first; rela_node; rela_node = rela_node->next) {
				rela = rela_node->elem;

				if (rela->type == SYMBOL_FUNCTION) {
					// If it is a relocation toward a function, we must make
					// sure that the function from the new version is referred,
					// not the original one

					bzero(name, sizeof(name));
					strcpy(name, rela->name);
					strcat(name, "_");
					strcat(name, suffix);

					// We seek the correct function by its name
					// (this should work, provided that cloning of functions
					// and instructions occurs before cloning relocations)
					sym = find_symbol_by_name(name);

					if (sym == NULL) {
						hinternal();
					}

					clone = symbol_rela_clone(sym);
					// We need to copy everything since we're cloning an
					// authentic symbol which has no relocation information
					clone->relocation.type = rela->relocation.type;
					clone->relocation.sec = rela->relocation.sec;
					clone->relocation.offset = rela->relocation.offset;
					clone->relocation.addend = rela->relocation.addend;
				}

				else if (rela->type == SYMBOL_SECTION && rela->sec->type == SECTION_CODE) {
					hinternal();
				}

				else {
					// We only need to update the section information
					clone = symbol_rela_clone(rela);
					clone->relocation.sec = func->symbol->sec;
				}

				clone->relocation.target_insn = instr;
				ll_push(&instr->reference, clone);
			}

			// --------------------------------------------------------
			// From * to CODE
			// --------------------------------------------------------

			for (rela_node = instr->parent->pointedby.first; rela_node; rela_node = rela_node->next) {
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
				clone->relocation.offset = rela->relocation.offset;

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
		if (sec->type == SECTION_CODE) {
			continue;
		}

		linked_list relocs = { NULL, NULL };

		// Get all relocations in `sec` to `text`, ordered by offset
		// and picked from the global list of symbols `symbols`
		find_relocations(symbols, sec, text->sym, &relocs);

		// Consume the ordered list by picking the first relocation
		// each time, in order to respect the offset ordering
		// enforced above
		while(!ll_empty(&relocs)) {
			rela = ll_pop_first(&relocs);

			if (rela->version == 0) {
				// We are asking for relocations toward `text`, which is
				// a section belonging to a version strictly greater
				// than 0
				hinternal();
			}

			if (rela->relocation.target_insn == NULL) {
				// All relocations towards CODE sections should have the
				// `target_insn` field populated
				hinternal();
			}

			for (rela2 = symbols; rela2; rela2 = rela2->next) {
				if (rela2->authentic == true
					  || rela2->version != version
					  || rela2->relocation.sec != text) {
					continue;
				}

				if (rela2->relocation.target_insn == NULL) {
					hinternal();
				}

				if (rela->relocation.sec == rela2->sec
				    && rela->relocation.offset == rela2->relocation.addend) {
					// We *MIGHT* have found the beginning of a branch table.

					rela2->relocation.addend = sec->sym->size;

					hnotice(3, "Updated CODE->* relocation in <%s + %x> to <%s + %x>\n",
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

			hnotice(3, "Updated *->CODE relocation in <%s + %x> to <%s + %x>\n",
				rela->relocation.sec->name, rela->relocation.offset,
					rela->name, rela->relocation.addend);
		}
	}
}


// static void clone_jump_tables(symbol *symbols, int version, section *text) {
// 	section *rodata;
// 	symbol *sym, *rela;
// 	function *func;
// 	insn_info *instr;

// 	ll_node *ref_node;

// 	unsigned int offset;

// 	// Rather than creating as many read-only sections as the number of executable
// 	// versions, we reuse the same '.rodata' section for all versions. Specifically,
// 	// the new relocation entries will have offsets that fall outside of '.rodata's
// 	// original boundaries. The proper size will be later computed in the emit step.
// 	rodata = find_section_by_name((unsigned char *)".rodata", 0);

// 	if (!rodata) {
// 		hnotice(4, "Missing '.rodata' section, no relocation entries to clone\n");
// 		return;
// 	}

// 	// We begin from the next byte after the end of '.rodata'
// 	offset = rodata->sym->size;

// 	// We order relocations in '.rodata' to '.text.xyz' according to their offsets
// 	// from the beginning of '.rodata'
// 	linked_list ordered = { NULL, NULL };

// 	find_relocations(symbols, rodata, text->sym, &ordered);

// 	// We now iteratively compare .rodata->.text.xyz relocations against all the
// 	// known instructions in the IBR, to see if there's a match
// 	while (!ll_empty(&ordered)) {
// 		sym = ll_pop_first(&ordered);

// 		if (sym->version > 0) {
// 			continue;
// 		}

// 		for (func = PROGRAM(v_code)[version]; func; func = func->next) {
// 			for (instr = func->begin_insn; instr; instr = instr->next) {

// 				for (ref_node = instr->parent->reference.first; ref_node; ref_node = ref_node->next) {
// 					rela = ref_node->elem;

// 					// We check if the instruction refers the beginning of a jump table
// 					if (rela->sec == sym->relocation.sec
// 						  && rela->relocation.addend == sym->relocation.offset) {
// 						// We *MIGHT* have found the beginning of a jump table.
// 						// As such, the original symbol must be duplicated and its offset must be
// 						// updated accordingly (since the entire jump table is duplicated)

// 						rela = symbol_rela_clone(rela);
// 						rela->version = version;

// 						// rela->relocation.offset = instr->reference->relocation.offset;
// 						rela->relocation.addend = offset;
// 						// rela->relocation.type = instr->reference->relocation.type;
// 						rela->relocation.sec = text;

// 						ll_push(&instr->reference, rela);
// 						rela->relocation.target_insn = instr;

// 						hnotice(3, "Added new jumptable base address relocation in <%s + %x> to <%s + %x>\n",
// 							rela->relocation.sec->name, rela->relocation.offset,
// 								rela->name, rela->relocation.addend);
// 					}

// 					else if (instr->orig_addr == sym->relocation.addend + sym->relocation.sec->offset) {
// 					}

// 				}
// 			}

// 		}

// 		offset += sizeof(char *);
// 		rodata->sym->size += sizeof(char *);
// 	}

// 	hnotice(4, "Added new relocation entries in '.rodata' section (%d bytes)\n",
// 		rodata->sym->size);
// }


// static void clone_func_relocation(int version, unsigned char *suffix) {
// 	function *func, *target_func;
// 	symbol *sym;
// 	insn_info *instr;

// 	unsigned char name[256];

// 	for (func = PROGRAM(v_code)[version]; func; func = func->next) {
// 		for (instr = func->begin_insn; instr; instr = instr->next) {
// 			sym = instr->reference;

// 			if (!IS_CALL(instr) && sym && sym->type == SYMBOL_FUNCTION) {
// 				hnotice(3, "Found function '%s' relocation to the instruction '%s' at address <%#08llx>\n",
// 					sym->name, instr->i.x86.mnemonic, instr->orig_addr);

// 				bzero(name, sizeof(name));
// 				strcpy(name, sym->name);
// 				strcat(name, "_");
// 				strcat(name, suffix);

// 				for (target_func = PROGRAM(v_code)[version]; target_func; target_func = target_func->next) {
// 					if (str_equal(target_func->name, name)) {
// 						hnotice(3, "Updating relocation with reference to new function '%s'\n",
// 							target_func->symbol->name);

// 						symbol_instr_rela_create(target_func->symbol, instr, RELOC_ABS_32);
// 						break;
// 					}
// 				}
// 			}
// 		}
// 	}
// }

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
	// otherwise it creates a new one by cloning the whole code
	// (symbols are not copied since they are shared among versions)

	if(!PROGRAM(v_code)[version]) {
		hnotice(3, "Version not present, cloning the binary representation...\n");

		suffix = (char *) (config.rules[version]->suffix);

		// Clones the whole code (function symbols included) from the plain version
		// to the new one, by appending the user-defined suffix to each name
		PROGRAM(v_code)[version] = clone_function_list(PROGRAM(v_code)[0], suffix);

		// A new section symbol is created that represents the .text.xyz section
		// holding the current version's code. This step is mandatory to have the
		// relocation towards the .text.xyz section aligned for the switch cases.
		// bzero(name, sizeof(name));
		// strcpy(name, ".text.");
		// strcat(name, suffix);
		// text = create_symbol_node((unsigned char *)name, SYMBOL_SECTION, SYMBOL_LOCAL, 0);

		clone_text_sections(version, suffix);

		clone_relocations(version, suffix);

		// For each text section S in the new version, we adjust relocations
		// from X->S in order to create room for new data in X.
		// This hopefully covers cases such as branch tables and other
		// pointers going around in town.

		for (text = PROGRAM(sections)[version]; text; text = text->next) {
			adjust_relocations(PROGRAM(symbols), version, text);
		}

		// Relinking jump instructions. Once cloned, instructions are no more
		// linked together; this task belongs to the parsing stage, nevertheless
		// we have to re-execute it in order to realign the representation's semantics
		// During the cloning operation, each instruction will be unreferenced, otherwise
		// we they still points to the old original copy, which would be incorrect!

		for (func = PROGRAM(v_code)[version]; func; func = func->next) {
			link_jump_instructions(func);
		}

		// Eventually, a new CFG is created for this version
		PROGRAM(blocks)[version] = block_graph_create(PROGRAM(v_code)[version]);

		// Update the executable versions array
		PROGRAM(code) = PROGRAM(v_code)[version];

		// The overall number of handled versions has to be increased
		PROGRAM(versions)++;

		hnotice(4, "Version %d of the executable's binary representation created\n", version);
	}

	hnotice(3, "Switched to version %d\n\n", version);

	return PROGRAM(version);
}
