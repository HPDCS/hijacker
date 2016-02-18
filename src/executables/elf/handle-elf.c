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
	// it containts.

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

		// func->symbol = clone->sym;
		func->symbol->sec = clone;
	}
}


static void clone_text_relocation(function *func, int version, char *suffix) {
	insn_info *instr;

	ll_node *sym_node;

	symbol *sym, *clone, *callee;

	unsigned char name[256];

	for (instr = func->begin_insn; instr; instr = instr->next) {

		for (sym_node = instr->parent->reference.first; sym_node; sym_node = sym_node->next) {
			sym = sym_node->elem;

			if (sym->type == SYMBOL_SECTION && str_equal(sym->sec->name, ".rodata")) {
				// Skip this part, it is handled by `clone_rodata_relocation`
				continue;
			}

			clone = symbol_rela_clone(sym);
			clone->relocation.target_insn = instr;
			clone->relocation.sec = func->symbol->sec;

			// It's a relocation toward a function, so we must update
			// symbol-specific information
			if (sym->type == SYMBOL_FUNCTION) {
				bzero(name, sizeof(name));
				strcpy(name, sym->name);
				strcat(name, "_");
				strcat(name, suffix);

				callee = find_symbol_by_name(name);

				if (callee == NULL) {
					hinternal();
				}

				// This is a trick: we treat `callee->symbol` as a relocation
				// entry, which is later filled with relocation information
				// from `clone`
				sym = symbol_rela_clone(callee);
				memcpy(&sym->relocation, &clone->relocation, sizeof(struct _relocation));

				clone = sym;
			}

			ll_push(&instr->reference, clone);
		}
	}
}


static void clone_rodata_relocation(symbol *symbols, int version, section *text) {
	section *rodata;
	symbol *sym, *rela;
	function *func;
	insn_info *instr;

	ll_node *ref_node;

	unsigned int offset;

	// Rather than creating as many read-only sections as the number of executable
	// versions, we reuse the same '.rodata' section for all versions. Specifically,
	// the new relocation entries will have offsets that fall outside of '.rodata's
	// original boundaries. The proper size will be later computed in the emit step.
	rodata = find_section_by_name((unsigned char *)".rodata", 0);

	if (!rodata) {
		hnotice(4, "Missing '.rodata' section, no relocation entries to clone\n");
		return;
	}

	// We begin from the next byte after the end of '.rodata'
	offset = rodata->sym->size;

	// We order relocations in '.rodata' to '.text.xyz' according to their offsets
	// from the beginning of '.rodata'
	linked_list ordered = { NULL, NULL };

	find_relocations(symbols, rodata, text->sym, &ordered);

	// We now iteratively compare .rodata->.text.xyz relocations against all the
	// known instructions in the IBR, to see if there's a match
	while (!ll_empty(&ordered)) {
		sym = ll_pop_first(&ordered);

		if (sym->version > 0) {
			continue;
		}

		for (func = PROGRAM(v_code)[version]; func; func = func->next) {
			for (instr = func->begin_insn; instr; instr = instr->next) {

				for (ref_node = instr->parent->reference.first; ref_node; ref_node = ref_node->next) {
					rela = ref_node->elem;

					// We check if the instruction refers the beginning of a jump table
					if (rela->sec == sym->relocation.sec
						  && rela->relocation.addend == sym->relocation.offset) {
						// We *MIGHT* have found the beginning of a jump table.
						// As such, the original symbol must be duplicated and its offset must be
						// updated accordingly (since the entire jump table is duplicated)

						rela = symbol_rela_clone(rela);
						rela->version = version;

						// rela->relocation.offset = instr->reference->relocation.offset;
						rela->relocation.addend = offset;
						// rela->relocation.type = instr->reference->relocation.type;
						rela->relocation.sec = text;

						ll_push(&instr->reference, rela);
						rela->relocation.target_insn = instr;

						hnotice(3, "Added new jumptable base address relocation in <%s + %x> to <%s + %x>\n",
							rela->relocation.sec->name, rela->relocation.offset,
								rela->name, rela->relocation.addend);
					}

					else if (instr->orig_addr == sym->relocation.addend + sym->relocation.sec->offset) {
						// If the instruction address is referred to by a relocation, duplicate
						// the latter and update pointers in the intermediate representation
						// so that the original relocation from version 0 and the instruction from
						// the current version aren't linked anymore
						rela = symbol_rela_clone(text->sym);
						rela->version = version;

						rela->relocation.offset = offset;
						// rela->relocation.addend = sym->relocation.addend;
						// rela->relocation.type = sym->relocation.type;
						rela->relocation.sec = rodata;

						ll_push(&instr->pointedby, rela);
						rela->relocation.target_insn = instr;

						hnotice(3, "Added new indirect relocation in <%s + %x> to <%s + %x>\n",
							rela->relocation.sec->name, rela->relocation.offset,
								rela->name, rela->relocation.addend);
					}

				}
			}

		}

		// TODO: It is safe to suppose that relocations are always 8 bytes long?
		offset += sizeof(char *);
		rodata->sym->size += sizeof(char *);
	}

	hnotice(4, "Added new relocation entries in '.rodata' section (%d bytes)\n",
		rodata->sym->size);
}


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

		// Text sections are cloned, too...
		clone_text_sections(version, suffix);

		// A new section symbol is created that represents the .text.xyz section
		// holding the current version's code. This step is mandatory to have the
		// relocation towards the .text.xyz section aligned for the switch cases.
		// bzero(name, sizeof(name));
		// strcpy(name, ".text.");
		// strcat(name, suffix);
		// text = create_symbol_node((unsigned char *)name, SYMBOL_SECTION, SYMBOL_LOCAL, 0);

		// Clone rodata relocations
		for (text = PROGRAM(sections)[version]; text; text = text->next) {
			clone_rodata_relocation(PROGRAM(symbols), version, text);
		}

		// Clone text relocations
		for (func = PROGRAM(v_code)[version]; func; func = func->next) {
			clone_text_relocation(func, version, suffix);
		}

		// We must also take into account indirect function invocations
		// clone_func_relocation(version, suffix);

		// Relinking jump instructions. Once cloned, instructions are no more
		// linked together; this task belongs to the parsing stage, nevertheless
		// we have to re-execute it in order to realign the representation's semantics
		// During the cloning operation, each instruction will be unreferenced otherwise
		// we they still points to the old original copy, which would be incorrect!

		for (func = PROGRAM(v_code)[version]; func; func = func->next) {
			link_jump_instructions(func);
		}

		// Eventually, a new CFG is created for this version
		PROGRAM(blocks)[version] = block_graph_create(PROGRAM(v_code)[version]);

		if (config.verbose > 2) {
			block_tree_dump("treedump.txt", "a+");
			block_graph_dump(PROGRAM(v_code)[version], "graphdump.txt", "a+");
		}

		hnotice(3, "Version %d of the executable's binary representation created\n", version);

		// Update the executable versions array
		PROGRAM(code) = PROGRAM(v_code)[version];

		// The overall number of handled versions has to be increased
		PROGRAM(versions)++;
	}

	hnotice(3, "Switched to version %d\n\n", version);

	return PROGRAM(version);
}
