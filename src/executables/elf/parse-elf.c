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
* @file parse-elf.c
* @brief Transforms an ELF object file in the hijacker's intermediate representation
* @author Alessandro Pellegrini
* @author Davide Cingolani
* @author Simone Economo
* @date September 19, 2008
*/

#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <endian.h>
#include <string.h>
#include <limits.h>

#include <hijacker.h>
#include <prints.h>
#include <executable.h>
#include <instruction.h>
#include <utils.h>

#include <elf/elf-defs.h>
#include <elf/handle-elf.h>
#include <x86/x86.h>



// FIXME: is this really used?
unsigned char *strtab(unsigned int byte) {

	// This will give immediate access to the symbol table's string table,
	// and will be populated upon the first execution of this function.
	static unsigned int sym_strtab = UINT_MAX;

	register unsigned int i;

	if(sym_strtab == UINT_MAX) { // First invocation: must lookup the table!
		for(i = 0; i < ELF(secnum); i++) {
			if(sec_type(i) == SHT_STRTAB && shstrtab_idx() != i) {
				sym_strtab = i;
				break;
			}
		}
	}

	// I assume that if this function was called, at least one symbol
	// is present, so at least one name is, and therefore at least one
	// string table is present, so I don't check if the table does
	// not exist!


	// Now get displace in the section and return
	return (unsigned char *)(sec_content(sym_strtab) + byte);
}



static void elf_raw_section(int secndx) {
	section *sec;

	// We do not need to perform any particular task here...

	// TODO: Check payloads
	if (sec_test_flag(secndx, SHF_TLS)) {
		sec = section_create_from_ELF(secndx, SECTION_TLS);
	} else {
		sec = section_create_from_ELF(secndx, SECTION_RAW);
	}

	if (sec_type(secndx) & SHT_PROGBITS) {
		hdump(4, sec_name(secndx), sec_content(secndx), sec_size(secndx));
	} else {
		sec->payload = NULL;
	}

	hsuccess();
}



static void elf_code_section(int secndx) {
	section *sec;
	insn_info *first, *instr, *prev;

	size_t pos, size;
	unsigned char flags;

	pos = 0;
	size = sec_size(secndx);
	flags = 0;

	// Preset some runtime parameters for instruction set decoding (when needed)
	switch(PROGRAM(insn_set)) {

		case X86_INSN:
			if(ELF(is64)) {
				flags |= DATA_64;
				flags |= ADDR_64;
			} else {
				flags |= DATA_32;
				flags |= ADDR_32;
			}
			break;

	}

	// Decode instructions and build functions map
	// NOTE: At this time, we consider the sections just as a sequence of instructions.
	// Later, a second pass on this sequence will divide instructions in functions,
	// but we must be sure to have symbols loaded, which we cannot be at this
	// stage of processing.

	first = instr = prev = NULL;

	while(pos < size) {
		instr = (insn_info *) calloc(sizeof(insn_info), 1);

		switch(PROGRAM(insn_set)) {

			case X86_INSN:
				x86_disassemble_instruction(sec_content(secndx), &pos, &instr->i.x86, flags);

				hnotice(5, "%#08lx: %s (%d)\n",
					instr->i.x86.initial, instr->i.x86.mnemonic, instr->i.x86.opcode_size);

				hdump(5, "Disassembly", instr->i.x86.insn, 15);

				// Make flags arch-independent
				instr->flags = instr->i.x86.flags;
				instr->new_addr = instr->orig_addr = instr->i.x86.initial;
				instr->size = instr->i.x86.insn_size;
				instr->opcode_size = instr->i.x86.opcode_size;

				instr->secname = sec_name(secndx);

				//hprint("%s, %s works on stack\n", instr->i.x86.mnemonic, instr->i.x86.flags & I_STACK ? "" : "not");
				// hprint("ISTRUZIONE:: '%s' -> opcode = %hhx%hhx, opsize = %d, insn_size = %d; breg = %x, "
				// 		"ireg = %x; disp_offset = %lx, jump_dest = %lx, scale = %lx, span = %lx\n",
				// 		instr->i.x86.mnemonic, instr->i.x86.opcode[1], instr->i.x86.opcode[0], instr->i.x86.opcode_size, instr->i.x86.insn_size,
				// 		instr->i.x86.breg, instr->i.x86.ireg, instr->i.x86.disp_offset, instr->i.x86.jump_dest,
				// 		instr->i.x86.scale, instr->i.x86.span);

				break;

			default:
				hinternal();
		}

		if (prev == NULL) {
			first = instr;
		} else {
			instr->prev = prev;
			prev->next = instr;
		}

		prev = instr;
	}

	sec = section_create_from_ELF(secndx, SECTION_CODE);
	sec->payload = first;

	hsuccess();
}



static void elf_symbol_section(int secndx) {
	section *sec;

	Elf_Sym *s;
	symbol *symbols, *sym;

	size_t pos, size;

	sec = section_create_from_ELF(secndx, SECTION_SYMBOLS);
	symbols = NULL;
	pos = 0;
	size = sec_size(secndx);

	while(pos < size) {
		s = (Elf_Sym *)(sec_content(secndx) + pos);

		sym = symbol_create_from_ELF(s);

		if (symbols == NULL) {
			symbols = sym;
		}

		pos += (ELF(is64) ? sizeof(Elf64_Sym) : sizeof(Elf32_Sym));
	}

	sec->payload = symbols;

	hsuccess();
}



static void elf_rel_section(int secndx) {
	section *sec;

	Elf_Rel *r;
	reloc *first, *rel, *prev;

	size_t pos, size;
	unsigned long long relinfo;

	pos = 0;
	size = sec_size(secndx);

	first = rel = prev = NULL;

	// Symbols and relocations are linked in a future pass, when all
	// program symbols and relocations are available

	while(pos < size) {
		rel = (reloc *) calloc(sizeof(reloc), 1);

		r = (Elf_Rel *) (sec_content(secndx) + pos);
		relinfo = reloc_info(r, r_info);

		rel->type = ELF(is64) ? ELF64_R_TYPE(relinfo) : ELF32_R_TYPE(relinfo);
		rel->offset = reloc_info(r, r_offset);
		rel->symnum = ELF(is64) ? ELF64_R_SYM(relinfo) : ELF32_R_SYM(relinfo);
		rel->secnum = sec_field(secndx, sh_info);

		// TODO: Retrieve the addend embedded into the instruction!

		hnotice(2, "Relocation %d refers to symbol %d at section %d + <%#08llx>\n",
			rel->type, rel->symnum, rel->secnum, rel->offset);

		if (prev == NULL) {
			first = rel;
		} else {
			prev->next = rel;
		}

		prev = rel;
		pos += (ELF(is64) ? sizeof(Elf64_Rel) : sizeof(Elf32_Rel));
	}

	sec = section_create_from_ELF(secndx, SECTION_RELOC);
	sec->payload = first;

	hsuccess();
}



static void elf_rela_section(int secndx) {
	section *sec;

	Elf_Rela *r;
	reloc *first, *rel, *prev;

	size_t pos, size;
	unsigned long long relinfo;

	pos = 0;
	size = sec_size(secndx);

	first = rel = prev = NULL;

	// Symbols and relocations are linked in a future pass, when all
	// program symbols and relocations are available

	while(pos < size) {
		rel = (reloc *) calloc(sizeof(reloc), 1);

		r = (Elf_Rela *) (sec_content(secndx) + pos);
		relinfo = reloc_info(r, r_info);

		rel->type = ELF(is64) ? ELF64_R_TYPE(relinfo) : ELF32_R_TYPE(relinfo);
		rel->offset = reloc_info(r, r_offset);
		rel->symnum = ELF(is64) ? ELF64_R_SYM(relinfo) : ELF32_R_SYM(relinfo);
		rel->secnum = sec_field(secndx, sh_info);
		rel->addend = reloc_info(r, r_addend);

		hnotice(2, "Relocation %d refers to symbol %d + %d at section %d + <%#08llx>\n",
			rel->type, rel->symnum, rel->addend, rel->secnum, rel->offset);

		if (prev == NULL) {
			first = rel;
		} else {
			prev->next = rel;
		}

		prev = rel;
		pos += (ELF(is64) ? sizeof(Elf64_Rela) : sizeof(Elf32_Rela));
	}

	sec = section_create_from_ELF(secndx, SECTION_RELOC);
	sec->payload = first;

	hsuccess();
}


static void elf_string_section(int secndx) {
	section *sec;

	unsigned char *stringtab, *name;

	size_t pos, size;

	pos = 0;
	size = sec_size(secndx);

	stringtab = (char *) malloc(sizeof(char) * size);

	while(pos < size){
		name = (sec_content(secndx) + pos);
		strcpy(stringtab + pos, (char *)name);

		hnotice(2, "%#08x: '%s'\n", pos, stringtab + pos);

		pos += (strlen((const char *) name) + 1);
	}

	// TODO: is this needed?
	sec = section_create_from_ELF(secndx, SECTION_NAMES);
	sec->payload = stringtab;

	hsuccess();
}



static function *resolve_function_symbol(symbol *sym) {
	function *func;
	section *sec;
	insn_info *instr;

	// Check if the section the symbol belongs to exists
	// and is actually a section containing code
	sec = find_section(sym->secnum);

	if (sec == NULL || sec->type != SECTION_CODE) {
		hinternal();
	}

	sym->sec = sec;

	// if (sym->bind == SYMBOL_WEAK && str_equal(sym->name, sec->name)) {
	// 	return NULL;
	// }

	// Retrieve the first instruction of the function by
	// reaching the instruction pointed to by the symbol position
	instr = find_insn_cool(sec->payload, sym->offset);

	if (!instr) {
		hinternal();
	}

	// Populate the new function object
	func = calloc(sizeof(function), 1);

	if (func == NULL) {
		herror(true, "Out of memory!\n");
	}

	func->name = sym->name;
	func->begin_insn = instr;

	// This is an important step to support multiple '.text' sections.
	// The base address of the function is the relative address from
	// the beginning of the section, plus the offset of the section
	// from the beginning of the file object. This value is later used
	// to re-compute the addresses of all the instructions.
	// func->orig_addr = func->new_addr = sym->offset + sec->offset;

	hnotice(2, "Function '%s' (%d bytes long) :: <%#08llx> (<%#08llx>)\n",
		sym->name, sym->size, sym->offset, func->begin_insn->orig_addr);

	func->symbol = sym;
	sym->func = func;

	return func;
}


static void resolve_variable_symbol(symbol *sym) {
	// We discard SHN_COMMON symbols because they refer to unallocated symbols,
	// therefore no further processing is needed. For every other symbols,
	// the symbol's payload is copied into a private buffer, then later
	// flushed to the new ELF file during the emit step

	// NOTE: SHN_COMMON also refers to Fortran COMMON symbols.

	hnotice(2, "Variable '%s' (%d bytes long) :: %lld (%s)\n",
		sym->name, sym->size, sym->offset,
			sym->secnum == SHN_COMMON ? "COM" : sec_name(sym->secnum));

	// TODO: Skip other special section indexes
	if (sym->secnum != SHN_COMMON) {
		sym->payload = calloc(sym->size, 1);
		sym->sec = find_section(sym->secnum);

		if (sec_type(sym->secnum) & SHT_PROGBITS) {
			memcpy(sym->payload, sec_content(sym->secnum) + sym->offset, sym->size);
		}

		hdump(5, sym->name, sym->payload, sym->size);
	}
}


static void resolve_section_symbol(symbol *sym) {
	section *sec;

	sym->name = (unsigned char *) sec_name(sym->secnum);
	sym->size = sec_size(sym->secnum);

	hnotice(2, "Section symbol %s (%d bytes long) pointing to section %d (%s)\n",
		sym->name, sym->size, sym->secnum, sec_name(sym->secnum));

	sec = find_section(sym->secnum);

	if (sec) {
		sec->sym = sym;
		sym->sec = sec;
	}

	// TODO: Cosa fare con simboli che riferiscono sezioni non parsate?

	// NOTE: There's no symbol equivalent for .rela.xyz sections!
}


/**
 * Resolves symbols by retrieving their types and calling the relative routine to handle them correctly.
 * At the end of the phase, instructions within the code section are translated into in-memory function objects
 * and returned into the global variable 'functions', whereas variables' values are stored into a data array.
 */
static void resolve_symbols(void) {
	section *sec;
	symbol *sym;
	function *first, *func, *curr, *prev;
	insn_info *instr;

	// Find first occurrence of a symbol table
	// TODO: Eventually multiple symbol tables should be supported
	for (sec = PROGRAM(sections)[0]; sec; sec = sec->next) {
		if (sec->type == SECTION_SYMBOLS) {
			break;
		}
	}

	if (sec == NULL) {
		hinternal();
	}

	hnotice(1, "Resolving symbols...\n");

	first = NULL;

	for (sym = sec->payload; sym; sym = sym->next) {

		switch(sym->type) {

			case SYMBOL_FUNCTION:
				func = resolve_function_symbol(sym);

				if (func) {
					// We maintain an ordered list of functions according to their
					// parent sections and their absolute addresses.
					for (prev = NULL, curr = first; curr; prev = curr, curr = curr->next) {
						if (func->symbol->sec == curr->symbol->sec &&
						    func->begin_insn->orig_addr <= curr->begin_insn->orig_addr) {
							break;
						}
					}

					if (prev == NULL) {
						first = func;
						func->next = curr;
					} else {
						prev->next = func;
						func->next = curr;
					}
				}

				break;

			case SYMBOL_VARIABLE:
			case SYMBOL_TLS:
				resolve_variable_symbol(sym);
				break;

			case SYMBOL_SECTION:
				resolve_section_symbol(sym);
				break;

			case SYMBOL_UNDEF:
				hnotice(2, "Undefined symbol '%s' (%d bytes long)\n", sym->name, sym->size);
				break;

			case SYMBOL_FILE:
				hnotice(2, "Filename's symbol\n");
				break;

			default:
				hnotice(2, "Unknown type for symbol '%s', skipped\n", sym->name);

		}
	}

	// Now, we must find function ends. This task ends up being more complex
	// than needed, since it is not possible to just seek RET instructions.
	// Indeed, they can be used in the middle of a function for optimization
	// purposes. In the end, the only reliable way to split functions is to use
	// the first instruction of the next function.

	for (prev = NULL, func = first; func; prev = func, func = func->next) {
		if (func->begin_insn->prev) {
			prev->end_insn = func->begin_insn->prev;
			prev->end_insn->next = NULL;
			func->begin_insn->prev = NULL;
		}
	}

	for (instr = prev->begin_insn; instr->next; instr = instr->next);

	prev->end_insn = instr;

	// // Update instruction addresses so to take into account
	// // multiple '.text' sections
	// for (prev = NULL, func = first; func; prev = func, func = func->next) {

	// 	// Avoid updating instruction addresses multiple times.
	// 	// This check is needed because in some cases (e.g., C++ files)
	// 	// it is possible to have overlapping functions, that is functions
	// 	// whose base addresses are the same.
	// 	if (prev != NULL && func->orig_addr == prev->orig_addr) {
	// 		continue;
	// 	}

	// 	for (instr = func->begin_insn; instr; instr = instr->next) {
	// 		instr->orig_addr += func->symbol->sec->offset;
	// 		instr->new_addr = instr->orig_addr;
	// 	}
	// }

	PROGRAM(symbols) = sec->payload;
	PROGRAM(code) = first;
	PROGRAM(v_code)[0] = first;

	hsuccess();
}



/**
 * Resolves each relocation entry stored in previous phase, by looking for each symbol name and binding them
 * to the relative reference. In particular, in a function each instruction descriptor handles a 'reference'
 * void * pointer which can represent either a variable or a call instruction to a specific address.
 * In case of a reference to an 'undefined' symbol, which probably means an external library function, a
 * temporary NULL pointer is set.
 *
 * If the symbol or the code address referenced to by the relocation entry was not found,
 * a warning is issued, but the parsing goes on.
 *
 * Note: Requires that symbols have already been resolved!
 */
static void resolve_relocation(void) {
	section *sec, *target;
	reloc *rel;
	symbol *sym, *rela;

	function *func;
	insn_info *instr;

	unsigned long long addr;

	hnotice(1, "Resolving relocations...\n\n");

	// Cycle through all the relocation sections
	for (sec = PROGRAM(sections)[0]; sec; sec = sec->next) {
		if (sec->type != SECTION_RELOC) {
			continue;
		}

		hnotice(2, "Parsing relocation section '%s'\n", sec_name(sec->index));

		// Retrieve target section object from the knowledge of the
		// target section's index of the current relocation
		target = find_section(sec_field(sec->index, sh_info));

		if (target == NULL) {
			hinternal();
		}

		// Cycle through all the relocation entries in `sec`
		for (rel = sec->payload; rel; rel = rel->next) {

			if (rel->symnum == 0) {
				// We should never have relocations toward STN_UNDEF
				hinternal();
			}

			rel->sec = target;

			// We look for the symbol pointed by the relocation `rel`
			sym = find_symbol(rel->symnum);

			if (!sym) {
				hinternal();
			}

			rel->sym = sym;

			hnotice(3, "Parsing relocation at '%s' + <%#08llx> + %d to %s [%d]\n",
				rel->sec->name, rel->offset, rel->addend, sym->name, rel->symnum);

			// Create a "relocation symbol" to the target object
			rela = symbol_rela_create_from_ELF(rel);

			if (rel->sec->type == SECTION_CODE) {
				// The relocation applies to an instruction, so it is a CODE->*
				// kind of relocation ({where}->{to})

				// addr = rel->sec->offset + rel->offset;
				addr = rel->offset;

				func = find_func_cool(rel->sec, addr);

				if (!func) {
					hinternal();
				}

				instr = find_insn_cool(func->begin_insn, addr);

				if (!instr) {
					hinternal();
				}

				hnotice(4, "Relocation applies to instruction: <%#08llx> '%s'\n",
					instr->orig_addr, instr->i.x86.mnemonic);

				// The instruction object will be bound to the proper symbol.
				// This reference is read by the specific machine code emitter
				// that is in charge to handle the relocation
				rela->relocation.target_insn = instr;

				// This relocation applies to the current instruction towards some symbol,
				// therefore we must to add a new reference in the instruction's descriptor
				// in order to keep track of it. The reference will be lately resolved by
				// the specific emitter in the emit phase.
				// Note: we use a list since there may be more relocations that applies to
				// the same instruction.
				ll_push(&instr->reference, rela);

				// hnotice(2, "Added symbol reference to '%s' + <%#08llx> + %d\n\n",
				// 	sym->relocation.sec->name, rel->offset, rel->addend);
			}

			else if (rel->sym->type == SYMBOL_SECTION && rel->sym->sec->type == SECTION_CODE) {
				// If the section's flags are not EXEC_INSTR, then this means that
				// the relocation does not apply to an instruction but to another symbol;
				// e.g. a SECTION symbol, in case of generic references (.data, .bss, .rodata)

				// If we are here, the relocation is *->CODE, otherwise
				// an instruction would be found in the previous branch.

				// addr = rel->sym->sec->offset + rel->addend;
				addr = rel->addend;

				func = find_func_cool(rel->sym->sec, addr);

				if (!func) {
					// Relocation points to a ghost function!
					hinternal();
				}

				instr = find_insn_cool(func->begin_insn, addr);

				if (!instr) {
					// Relocation points to a ghost instruction!
					hinternal();
				}

				hnotice(4, "Instruction pointed to by relocation: <%#08llx> '%s'\n",
					instr->orig_addr, instr->i.x86.mnemonic);

				// Add the reference to the found instruction in the current relocation's
				// descriptor
				rela->relocation.target_insn = instr;

				// Add the reference that the currently found instruction has been referenced
				// by a relocation.
				// Note: we use list because one instruction can be referenced by more than
				// one relocation entry
				ll_push(&instr->pointedby, rela);

				// hnotice(2, "Added symbol reference to '%s' + <%#08llx> + %d\n\n",
				// 	sym->relocation.sec->name, rel->offset, rel->addend);
			}

			else {
				herror(false, "Relocation entry does not match any case\n");
				// hinternal();
			}
		}
	}

	hsuccess();
}



static void resolve_jumps(void) {
	link_jump_instructions();

	hsuccess();
}



static void resolve_blocks(void) {
	PROGRAM(blocks)[0] = block_graph_create();

	hsuccess();
}



void elf_create_map(void) {
	unsigned int size;
	unsigned int secndx;

	// Reserve space and load ELF in memory
	fseek(ELF(pointer), 0L, SEEK_END);
	size = ftell(ELF(pointer));
	rewind(ELF(pointer));

	ELF(data) = malloc(size * sizeof(unsigned char));
	if (fread(ELF(data), 1, size, ELF(pointer)) != size) {
		herror(true, "Unable to correctly load the ELF file\n");
	}
	rewind(ELF(pointer));

	// Keep track of the header
	ELF(hdr) = (Elf_Hdr *)ELF(data);

	// Where is the section header?
	if (ELF(is64)) {
		ELF(sec_hdr) = (Section_Hdr *)(ELF(data) + ELF(hdr)->header64.e_shoff);
	}	else {
		ELF(sec_hdr) = (Section_Hdr *)(ELF(data) + ELF(hdr)->header32.e_shoff);
	}

	// How many sections are in the ELF?
	if (ELF(is64)) {
		ELF(secnum) = ELF(hdr)->header64.e_shnum;
	} else {
		ELF(secnum) = ELF(hdr)->header32.e_shnum;
	}

	// Scan ELF Sections and convert/parse them (if any to be)
	for(secndx = 0; secndx < ELF(secnum); secndx++) {
		hnotice(1, "Parsing section %u of %u: '%s' (%d bytes long, offset %#08lx)\n",
			secndx, ELF(secnum), sec_name(secndx), sec_size(secndx), sec_field(secndx, sh_offset));

		switch(sec_type(secndx)) {
			case SHT_PROGBITS:
				if(sec_test_flag(secndx, SHF_EXECINSTR)) {
					// if (str_prefix(sec_name(secndx), ".text")) {
						// Filter out debug code sections
						// FIXME: Eventually they should be taken into account
						elf_code_section(secndx);
					// }
				} else {
					// It must be a data section
					elf_raw_section(secndx);
				}
				break;

			case SHT_SYMTAB:
				elf_symbol_section(secndx);
				break;

			case SHT_NOBITS:
				elf_raw_section(secndx);
				break;

			case SHT_REL:
				elf_rel_section(secndx);
				break;

			case SHT_RELA:
				if(str_prefix(sec_name(secndx), ".rela.text")) {
					// We need to include relocations toward unconventional text sections
					elf_rela_section(secndx);
				}
				else if(!strcmp(sec_name(secndx), ".rela.data")) {
					elf_rela_section(secndx);
				}
				else if(!strcmp(sec_name(secndx), ".rela.rodata")) {
					elf_rela_section(secndx);
				}
				else if(!strcmp(sec_name(secndx), ".rela.bss")) {
					elf_rela_section(secndx);
				}
				break;

			case SHT_STRTAB:
				elf_string_section(secndx);
				break;

			case SHT_HASH:
			case SHT_DYNAMIC:
			case SHT_DYNSYM:
				elf_raw_section(secndx);
				break;
		}
	}

	// Ultimates the binary representation
	resolve_symbols();
	resolve_relocation();

	update_instruction_addresses(0);
	update_jump_displacements(0);

	resolve_jumps();
	resolve_blocks();

	// Updates the binary representation's pointers

	PROGRAM(rawdata) = 0;
	PROGRAM(versions)++;

	hnotice(1, "ELF parsing terminated\n");
	hsuccess();
}



int elf_instruction_set(void) {
	Elf32_Ehdr hdr; // Headers are same sized. Assuming its 32 bits...
	int insn_set = UNRECOG_INSN;

	hnotice(1, "Determining instruction set... \n");

	// Load ELF Header
	if(fread(&hdr, 1, sizeof(Elf32_Ehdr), ELF(pointer)) != sizeof(Elf32_Ehdr)) {
		herror(true, "An error occurred while reading program header\n");
	}

	// Switch on proper field
	switch(hdr.e_machine) {

		case EM_386:
		case EM_X86_64:
			insn_set = X86_INSN;
			break;
		}


	if(insn_set == UNRECOG_INSN) {
		hfail();
	} else {
		hsuccess();
	}

	rewind(ELF(pointer));

	return insn_set;
}



bool is_elf(char *path) {
	Elf32_Ehdr hdr; // Headers are same sized. Assuming its 32 bits...

	hnotice(1, "Checking whether '%s' is an ELF executable...", path);

	// Try to oper the file
	ELF(pointer) = fopen(path, "r+");
	if(ELF(pointer) == NULL) {
		herror(true, "Unable to open '%s' for reading\n", path);
	}


	// Load ELF Header
	if(fread(&hdr, 1, sizeof(Elf32_Ehdr), ELF(pointer)) != sizeof(Elf32_Ehdr)) {
		herror(true, "An error occurred while reading program header\n");
	}

	// Is it a valid ELF?!
	if(hdr.e_ident[EI_MAG0] != ELFMAG0 ||
			hdr.e_ident[EI_MAG1] != ELFMAG1 ||
			hdr.e_ident[EI_MAG2] != ELFMAG2 ||
			hdr.e_ident[EI_MAG3] != ELFMAG3) {
		fclose(ELF(pointer));
		hfail();
		return false;
	}

	// We cannot deal with executables, only with relocatable objects
	if(hdr.e_type != ET_REL) {
		herror(true, "Can analyze only relocatable ELF objects\n");
	}

	// Is the current ELF 32- or 64-bits?
	switch(hdr.e_ident[EI_CLASS]) {
	case ELFCLASS32:
		ELF(is64) = false;
		break;
	case ELFCLASS64:
		ELF(is64) = true;
		break;
	default:
		herror(true, "Invalid ELF class\n");
	}

	// Reset the file descriptor
	rewind(ELF(pointer));

	hsuccess();
	return true;
}
