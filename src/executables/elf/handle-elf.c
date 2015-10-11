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
*/

#include <stdio.h>
#include <string.h>

#include <hijacker.h>
#include <prints.h>
#include <executable.h>
#include <instruction.h>

#include <elf/parse-elf.h>
#include <elf/handle-elf.h>


/**
 * In order to be linkable, new relocation nodes can be created in case
 * genereted instructions have to be referenced.
 *
 * @param sym Symbol descriptor of the symbol that will be referenced to
 * @param insn The pointer to the descritpor of the instruction who need to be relocated
 */
symbol *instruction_rela_node (symbol *sym, insn_info *insn, unsigned char type) {
  symbol *ref;    // a new relocation entry is a duplicate of the referenced symbol;
  long addend;

  hnotice(3, "Adding a RELA node to '%s'\n", sym->name);

  switch(type) {
    case RELOCATE_RELATIVE_32:
    case RELOCATE_RELATIVE_64:
      addend = (long)insn->opcode_size - (long)insn->size;
      // consider that the addend is backward and -(a - b) == (b - a)
      break;

    case RELOCATE_ABSOLUTE_32:
    case RELOCATE_ABSOLUTE_64:
      addend = 0;
      break;
  }

  switch(type) {
    case RELOCATE_RELATIVE_32:
      type = R_X86_64_PC32;
      break;

    case RELOCATE_RELATIVE_64:
      type = R_X86_64_PC64;
      break;

    case RELOCATE_ABSOLUTE_32:
      type = R_X86_64_32;
      break;

    case RELOCATE_ABSOLUTE_64:
      type = R_X86_64_64;
      break;

    case RELOCATE_TLS_RELATIVE_32:
      type = R_X86_64_TPOFF32;
      break;

    default:
      type = R_X86_64_PC32;
  }

  // Check if the symbol has already been referenced.
  // If this is the case, it returns a duplicate
  ref = symbol_check_shared(sym);
  ref->referenced = 1;
  ref->relocation.addend = addend;
  ref->relocation.type = type;
  ref->relocation.secname = (unsigned char *)".text";

  insn->reference = ref;

  hnotice(3, "New RELA node has been created from symbol '%s' (%d) %+ld to the instruction at address <%#08llx>\n",
    sym->name, sym->index, ref->relocation.addend, insn->new_addr);

  return ref;
}


void create_rela_node(symbol *sym, long long offset, long addend, unsigned char *secname) {
  char type;

  // Decide the relocation's type accordingly to the relocation specifications
  /*if(!strcmp((const char *)secname, ".text")) {

    // Relocatation applies in the .text section towards symbol 'sym'
    switch(sym->type) {
      case SYMBOL_SECTION:
        type = R_X86_64_32;
        break;

      default:
        type = R_X86_64_PC32;
    }
  } else if(!strcmp((const char *)secname, ".rodata")) {
    // Relocation applies in the .rodata section towards another section symbol
    type = R_X86_64_64;
  } else {
    // Default value
    type = R_X86_64_64;
  }*/

  sym = symbol_check_shared(sym);
  sym->referenced = 1;
  sym->relocation.addend = addend;
  sym->relocation.offset = offset;
  sym->relocation.type = type;
  sym->relocation.secname = secname;


  hnotice(3, "New RELA node of type %d has been created at %lld to symbol '%s' %ld in section '%s'\n",
    sym->relocation.type, sym->relocation.offset, sym->name, sym->relocation.addend, secname);
}


static void clone_rodata_relocation(symbol *original, function *code, int version, unsigned char *suffix) {
	symbol *sym, *text, *ref, *rodata;
	function *func;
	insn_info *instr;
	unsigned char name[256];
	unsigned int offset;
	// bool first = true;

	// A new section symbol is created that represents the .text.xyz section
	// holding the current version's code. This step is mandatory to have the
	// relocation towards the .text.xyz section aligned for the switch cases.
	bzero(name, sizeof(name));
	strcpy(name, ".text.");
	strcat(name, (unsigned char *)suffix);
	text = create_symbol_node((unsigned char *)name, SYMBOL_SECTION, SYMBOL_LOCAL, 0);

	// Rather than creating as many read-only sections as the number of executable
	// versions, we reuse the same '.rodata' section for all versions. Specifically,
	// the new relocation entries will have offsets that fall outside of '.rodata's
	// original boundaries. The proper size will be later computed in the emit step.
	rodata = find_symbol((unsigned char *)".rodata");
	if (!rodata) {
		hnotice(4, "Missing '.rodata' section, no relocation entries to clone\n");
		return;
	}

	offset = rodata->size;
	sym = original;
	while(sym) {

		// Looks for relocations in '.rodata' that refer to '.text' addresses
		// (i.e. case statements) from the original code
		if(sym->version == 0 && !strcmp((const char *)sym->name, ".text") &&
		   sym->relocation.secname != NULL && !strcmp((const char *)sym->relocation.secname, ".rodata")) {

			func = code;
			while(func) {

				instr = func->insn;
				while(instr) {

					ref = NULL;

					// If a relocation in '.text' refers to an address in '.rodata',
					// that address *MIGHT BE* the beginning of a jump table.
					// As such, the original symbol must be duplicated and its offset must be
					// updated accordingly (since the entire jump table is duplicated)
					if(instr->reference && instr->reference->relocation.addend == sym->relocation.offset &&
					   instr->reference->relocation.secname != NULL &&
					   !strcmp((const char *)instr->reference->relocation.secname, ".text") &&
					   !strcmp((const char *)instr->reference->name, ".rodata")) {

						ref = symbol_check_shared(instr->reference);

						ref->relocation.offset = instr->reference->relocation.offset;
						ref->relocation.addend = offset;
						ref->relocation.type = instr->reference->relocation.type;
						ref->relocation.secname = text->name;

						instr->reference = ref;
						ref->relocation.ref_insn = instr;
					}

					// If the instruction address is referred to by a relocation, duplicate
					// the latter and update pointers in the intermediate representation
					// so that the original relocation from version 0 and the instruction from
					// the current version aren't linked anymore
					else if(instr->new_addr == sym->relocation.addend) {
						ref = symbol_check_shared(text);

						ref->relocation.offset = offset;
						ref->relocation.addend = sym->relocation.addend;
						ref->relocation.type = sym->relocation.type;
						ref->relocation.secname = rodata->name;

						instr->pointedby = ref;
						ref->relocation.ref_insn = instr;
					}

					if (ref) {
						hnotice(5, "Added new relocation in <%s + %x> to <%s + %x>\n",
							ref->relocation.secname, ref->relocation.offset, ref->name, ref->relocation.addend);
					}

					instr = instr->next;
				}

				func = func->next;
			}

			// FIXME: Da identificare perché la prima rilocazione viene scritta
			// 8 byte più avanti rispetto alle altre. Questo workaround consente di
			// instrumentare le tabelle per gli switch case in alcune condizioni
			// che tuttavia non sono state ancora identificate...
			// offset += first ? 2 * sizeof(char *) : sizeof(char *);
			// first = false;

			// TODO: It is safe to suppose that relocations are always 8 bytes long?
			offset += sizeof(char *);
			rodata->size += sizeof(char *);
		}

		sym = sym->next;
	}

	hnotice(4, "Added new relocation entries in '.rodata' section (%d bytes)\n", rodata->size);
}


static void clone_func_relocation(function *code, int version, unsigned char *suffix) {
	function *func, *target_func;
	symbol *sym;
	insn_info *instr;

	unsigned char name[256];

	for (func = code; func; func = func->next) {
		for (instr = func->insn; instr; instr = instr->next) {
			sym = instr->reference;

			if (!IS_CALL(instr) && sym && sym->type == SYMBOL_FUNCTION) {
				hnotice(3, "Found function '%s' relocation to the instruction '%s' at address <%#08llx>\n",
					sym->name, instr->i.x86.mnemonic, instr->orig_addr);

				bzero(name, sizeof(name));
				strcpy(name, sym->name);
				strcat(name, "_");
				strcat(name, suffix);

				for (target_func = code; target_func; target_func = target_func->next) {
					if (!strcmp(target_func->name, name)) {
						hnotice(3, "Updating relocation with reference to new function '%s'\n",
							target_func->symbol->name);

						instruction_rela_node(target_func->symbol, instr, RELOCATE_ABSOLUTE_32);
						break;
					}
				}
			}
		}
	}
}

int switch_executable_version (int version) {
	function *func, *code;

	// Updates the current working version of the binary representation
	PROGRAM(version) = version;

	// Checks whether the version is already present in the list
	// otherwise it creates a new one by cloning the whole code
	// (symbols are not copied since they are shared among versions)
	if(!PROGRAM(v_code)[version]) {

		hnotice(3, "Version not present, cloning the binary representation...\n");

		// Clones the whole code (symbols are shared) from the plain version (0)
		// to the new one by appending the user-defined suffix to each new function
		code = func = clone_function_list(PROGRAM(v_code)[0], (char *)config.rules[version]->suffix);
		PROGRAM(v_code)[version] = code;

		clone_rodata_relocation(PROGRAM(symbols), code, version, (char *)config.rules[version]->suffix);

		// Relinking jump instructions. Once cloned, instructions are no more
		// linked together; this task belongs to the parsing stage, nevertheless
		// we have to re-execute it in order to realign the representation's semantics
		// During the cloning operation, each instruction will be unreferenced otherwise
		// we they still points to the old original copy, which would be incorrect!

		// Iterates all over the functions
		while(func) {
			link_jump_instructions(func, code);
			func = func->next;
		}

		// [SE]
		clone_func_relocation(code, version, (char *)config.rules[version]->suffix);

		PROGRAM(blocks)[version] = block_graph_create(code);

		block_tree_dump("treedump.txt", "a+");
		block_graph_dump(code, "graphdump.txt", "a+");
		// [/SE]

		hnotice(3, "Version %d of the executable's binary representation created\n", version);

		// The overall number of handled versions has to be increased
		PROGRAM(versions)++;
	}

	// Update the executable versions array
	PROGRAM(code) = PROGRAM(v_code)[version];

	hnotice(3, "Switched to version %d\n", version);

	return PROGRAM(version);
}
