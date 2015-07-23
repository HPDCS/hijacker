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
void instruction_rela_node (symbol *sym, insn_info *insn, unsigned char type) {
  symbol *ref;    // a new relocation entry is a duplicate of the referenced symbol;
  long addend;

  hnotice(3, "Adding a RELA node to '%s'\n", sym->name);

  switch(type) {
    case RELOCATE_RELATIVE_32:
    case RELOCATE_RELATIVE_64:
      addend = (long)insn->opcode_size - (long)insn->size;  // consider that the addend is backward and -(a - b) == (b - a)
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
	symbol *sym, *ref, *rodata;
	function *func;
	insn_info *instr;
	unsigned char name[256];
	unsigned int offset = 0;
	bool first = true;

	// Here we create also a new section symbol for the future
	// .text section that will contain the previously cloned functions.
	// This is a mandatory step in order to have the relocation towards
	// the .text.xyz section aligned for the switch cases
	bzero(name, sizeof(name));
	strcpy(name, ".text.");
	strcat(name, (unsigned char *)suffix);
	ref = create_symbol_node((unsigned char *)name, SYMBOL_SECTION, SYMBOL_LOCAL, 0);

	// We have create accordingly a new .rela.rodata.xyz in order to maintain aligned relocation
	// offsets within sections, otherwise they will overwrite each other during the final linking stage.
	// The new section is intended to handle switch cases, the remainder of the code should be fine.
	/*bzero(name, sizeof(name));
	strcpy(name, ".rodata.");
	strcat(name, (unsigned char *)suffix);
	from = create_symbol_node((unsigned char *)name, SYMBOL_SECTION, SYMBOL_LOCAL, 0);*/

	// We reuse the same .rodata section to adds the relocation entries to the instrumented text
	// without to create as many sections as the versions created. Therefore we will look for the
	// '.rodata' sections within the symbol list and retrieve its size to append at the end the new
	// entries.
	rodata = find_symbol((unsigned char *)".rodata");

	if (!rodata) {
		hnotice(4, "Missing '.rodata' section, no relocation entries to add\n");
		return;
	}

	offset = rodata->size;

	sym = original;
	while(sym) {

		// Looks for refrences which applies to .text section only
		// from .rodata (e.g. switch cases), from the original code
		if(!strcmp((const char *)sym->name, ".text") &&
			sym->relocation.secname != NULL &&
			!strcmp((const char *)sym->relocation.secname, ".rodata") &&
			sym->version == 0) {

			ref = symbol_check_shared(ref);

			ref->relocation.offset = offset;
			ref->relocation.addend = sym->relocation.addend;
			ref->relocation.type = sym->relocation.type;
			ref->relocation.secname = rodata->name;

			//printf("Cerco rilocazione verso .rodata contro .text con offset = %llx\n", sym->relocation.offset);

			func = code;
			while(func) {
				instr = func->insn;
				while(instr) {
					if(instr->reference && instr->reference->relocation.addend == sym->relocation.offset) {
						instr->reference = symbol_check_shared(instr->reference);
						instr->reference->relocation.addend = offset;

						//printf("Aggiornata rilocazione: <%#08llx>%+d\n", instr->reference->relocation.offset, instr->reference->relocation.addend);
					}

					if(instr->new_addr == sym->relocation.addend) {
						instr->pointedby = ref;
						ref->relocation.ref_insn = instr;

						//printf("Aggiornato il puntatore al simbolo che punta all'istruzione <%#08llx> alla versione %d\n", instr->new_addr, ref->version);
					}

					instr = instr->next;
				}

				func = func->next;
			}

			hnotice(5, "Updated rodata relocation: <%#08llx>%+d to '%s'\n",
				ref->relocation.offset, ref->relocation.addend, ref->relocation.secname);

			// Each relocation displaces of 4 bytes (32 bits) at a time
			// TODO: It is safe to suppose that relocations are always 8 bytes long?

			//FIXME: Da identificare perché la prima rilocazione viene scritta
			// 8 byte più avanti rispetto alle altre. Questo workaround consente di
			// instrumentare le tabelle per gli switch case in alcune condizioni
			// che tuttavia non sono state ancora identificate...
			offset += first ? 16 : 8;
			rodata->size += 8;
			first = false;
		}

		sym = sym->next;
	}

	hnotice(4, "Added new relocation entries in '.rodata' section (%d bytes)\n", rodata->size);
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

		// The overall number of handled versions has to be increased
		PROGRAM(versions)++;

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

		hnotice(3, "Version %d of the executable's binary representation created\n", version);
	}

	// Update the executable versions array
	PROGRAM(code) = PROGRAM(v_code)[version];

	hnotice(3, "Switched to version %d\n", version);

	return PROGRAM(version);
}
