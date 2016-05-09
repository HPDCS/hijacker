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
* @file emit-elf.c
* @brief Code to generate an ELF file from the Intermediate Representation
* @author Davide Cingolani
* @date May 20, 2014
*/

#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>

#include <hijacker.h>
#include <utils.h>
#include <prints.h>
#include <executable.h>

#include <elf/elf-defs.h>
#include <elf/handle-elf.h>
#include <elf/emit-elf.h>

/// Hijacked output ELF descriptor
hijacked_elf hijacked;

/**
 * Commodity pointers to default section's payloads
 */
static section *shstrtab;
static section *strtab;
static section *symtab;
static section *rodata;
static section *text[MAX_VERSIONS];
static section *rela_text[MAX_VERSIONS];
static section *rela_rodata;
static section *rela_data;
static section *data;
static section *bss;
static section *tbss;
static section *tdata;


/**
 * Check if the section has enough available space.
 * If the section cannot sustain the required space,
 * its size is automatically doubled.
 *
 * @param sec Section descriptor
 * @param span Integer representing the size to be written
 */
inline static void check_section_size(section *sec, int span) {
	Section_Hdr *hdr;
	unsigned long long offset, size;

	hdr = (Section_Hdr *) sec->header;

	offset = ((char *)sec->ptr - (char *)sec->payload);
	size = header_info(hdr, sh_size);

	hnotice(6, "Check if section '%s' (index %u) has enough available space "
		"(Available = %llu, Needed = %d, Offset = %llu)\n",
		sec->name, sec->index, (size - offset), span, offset);

	if (size == 0) {
		size = SECTION_INIT_SIZE;
	}

	if (sec->ptr == NULL) {
		sec->ptr = sec->payload = malloc(size);

		hnotice(6, "Allocated %llu bytes for section %u\n", size, sec->index);
	}

	while (((char *)sec->ptr + span) >= ((char *)sec->payload + size)) {
		size *= 2;

		sec->ptr = sec->payload = realloc(sec->payload, size);
		// Replace 'ptr' to the original displacement in the newly-allocated block
		sec->ptr = (void *)((char *)sec->ptr + offset);

		hnotice(6, "Doubling size of section %u to %llu...\n", sec->index, size);
	}

	// Update the size into the section header
	set_hdr_info(hdr, sh_size, size);
}


/**
 * Given a section it shrinks its size to the exact one
 *
 * @param sec Section descriptor
 * @return Returns the final size in bytes
 */
inline static long shrink_section_size(section *sec) {
	Section_Hdr *hdr;
	long size, old_size;

	hdr = sec->header;
	size = ((char *)sec->ptr - (char *)sec->payload);

	if (size < 0) {
		hinternal();
	}

	sec->payload = realloc(sec->payload, size);

	old_size = header_info(hdr, sh_size);
	set_hdr_info(hdr, sh_size, size);

	hnotice(3, "Section '%s' [%d] size shrink from %lld to %lld bytes\n",
		sec->name, sec->index, old_size, size);

	return size;
}


/**
 * Writes a string in the '.strtab' section and return the pointer of the
 * next available byte in the section.
 * Writes the passed string into the section's payload pointed to by 'sec'.
 *
 * @param sec Section to which write the new entry
 * @param buffer Pointer to the buffer containing the string to be written
 *
 * @return The offset of the written entry in the string table, or zero in case the buffer
 * is not provided.
 * In this case, by passing a 'NULL' value as buffer, every symbol will be mapped, as default,
 * to the empty string.
 */
long elf_write_string(section *sec, char *buffer) {
	Section_Hdr *hdr;
	int buflen;
	void *ptr;

	if (buffer == NULL) {
		return 0;
	}

	hdr = (Section_Hdr *) sec->header;
	buflen = strlen(buffer) + 1; // takes into account string terminator '\0'

	// Check if section size must be enlarged
	check_section_size(sec, buflen);

	// Copy buffer in the section payload
	strcpy(sec->ptr, buffer);

	// Save the old pointer to the newly written section area
	// and update the main section's payload pointer
	ptr = sec->ptr;
	sec->ptr = (void *)((char *)sec->ptr + buflen);

	hnotice(4, "String written to .strtab section at offset <%#08lx> :: '%s'\n",
		((char *)ptr - (char *)sec->payload), buffer);

	return (long)((char *)ptr - (char *)sec->payload);
}


/**
 * Writes a new data entry in the rodata section
 *
 * @param sec Data section to which write the entry
 * @param data Pointer to the buffer containing the data to be written
 * @param size Size of the buffer data to copy into the section
 *
 * @return The offset of the data written from section's beginning
 */
// long elf_write_rodata(section *sec, void *buffer, int size) {
// 	Section_Hdr *hdr;
// 	void *ptr;

// 	// check if section must be enlarged
// 	check_section_size(sec, size);

// 	hdr = (Section_Hdr *) sec->header;

// 	memcpy(sec->ptr, buffer, size);
// 	ptr = sec->ptr;
// 	sec->ptr = (void *)((char *)sec->ptr + size);

// 	hnotice(3, "Read-only data written into section '%s' [%d] at offset <%#08lx>\n",
// 		sec->name, sec->index, ((char *)ptr - (char *)sec->payload));

// 	hdump(4, "Data buffer dump", buffer, size);

// 	return (long)((char *)ptr - (char *)sec->payload);
// }


/**
 * Writes a new data entry in an allocated data section
 *
 * @param sec Data section to which write the entry
 * @param buffer Pointer to the buffer containing the data to be written
 * @param size Size of the buffer data to copy into the section
 *
 * @return The offset of the data written from section's beginning
 */
long elf_write_data(section *sec, void *buffer, int size) {
	Section_Hdr *hdr;
	void *ptr;

	// Check if section must be enlarged
	check_section_size(sec, size);

	hdr = (Section_Hdr *) sec->header;

	if (buffer != NULL) {
		memcpy(sec->ptr, buffer, size);
		hdump(4, "Data buffer dump", buffer, size);
	}

	ptr = sec->ptr;
	sec->ptr = (void *)((char *)sec->ptr + size);

	hnotice(3, "Data written into section '%s' [%d] at offset <%#08lx>\n",
		sec->name, sec->index, ((char *)ptr - (char *)sec->payload));


	return (long)((char *)ptr - (char *)sec->payload);
}


/**
 * Write a new symbol in the symbol section.
 * Takes the symbol and the section descriptor to write it on. A new symbol entry in the
 * ELF file will be prepared and the pointer to the new available location is returned.
 *
 * @param symtab Symbol section to which write the new symbol entry
 * @param sym Pointer to the symbol descriptor to be written
 * @param strtab Pointer to the string section's descriptor to which write the symtab's name
 * @param data Data section's descriptor to which store the symbol's payload
 *
 * @return Symbol index within the symbol table of the written entry
 */
int elf_write_symbol(section *symtable, symbol *sym, section *strtable) {
	Elf_Sym *entry;
	Elf64_Sym *sym64;
	Elf32_Sym *sym32;
	Section_Hdr *hdr;

	section *sec;

	size_t size, shndx;
	void *ptr;

	size = sym_size();

	// Build a new ELF symbol entry
	entry = (Elf_Sym *) calloc(size, 1);
	hdr = (Section_Hdr *) symtable->header;

	sec = NULL;
	shndx = 0;

	if(ELF(is64)) {
		sym64 = &(entry->sym64);

		switch(sym->type) {
		case SYMBOL_FUNCTION:
			// NOTE: Its starting offset it is already been evaluated in a previous pass
			// TODO: it must be updated in order to support multiple .text sections
			sec = text[sym->version];
			shndx = text[sym->version]->index;
			sym->type = STT_FUNC;
			break;

		case SYMBOL_VARIABLE:
			// Verify if the object has to be binded to the COMMON section,
			// that is the variable is not allocated yet; otherwise .data section
			// must be filled up with the relative content
			// TODO: it must be updated in order to support multiple .data sections
			if (sym->secnum != SHN_COMMON) {
				if (str_equal(sym->sec->name, ".data")) {
					// sym->offset = elf_write_data(data, sym->payload, sym->size);
					sec = data;
					shndx = data->index;
				}
				else if (str_equal(sym->sec->name, ".rodata")) {
					// sym->offset = elf_write_data(rodata, sym->payload, sym->size);
					shndx = rodata->index;
				}
				else if (str_equal(sym->sec->name, ".bss")) {
					sec = bss;
					shndx = bss->index;
				}
			} else {
				shndx = SHN_COMMON;
			}
			sym->type = STT_OBJECT;
			break;

		case SYMBOL_TLS:
			if (str_equal(sym->sec->name, ".tdata")) {
				sym->offset = elf_write_data(tdata, sym->payload, sym->size);
				sec = tdata;
				shndx = tdata->index;
			}
			else if (str_equal(sym->sec->name, ".tbss")) {
				sec = tbss;
				shndx = tbss->index;
			}
			sym->type = STT_TLS;
			break;

		case SYMBOL_SECTION:
			// Sections are always local symbols
			sym->bind = STB_LOCAL;
			sym->type = STT_SECTION;
			sec = sym->sec;
			shndx = sym->secnum;
			// sym->name = "";
			break;

		case SYMBOL_FILE:
			// File symbols are always local
			sym->bind = STB_LOCAL;
			sym->type = STT_FILE;
			shndx = SHN_ABS;
			break;

		case SYMBOL_UNDEF:
		default:
			// Since they are undefined, it is not possible to infer whether
			// local or global binding must be used, hence only the type will
			// be updated leaving the bind unaltered
			sym->type = STT_NOTYPE;
			shndx = SHN_UNDEF;
		}

		// Write the symbol name into the string_table and get the offset
		sym64->st_name = elf_write_string(strtable, (char *)sym->name);
		sym64->st_value = sym->offset;
		sym64->st_size = sym->size;
		sym64->st_info = ELF64_ST_INFO(sym->bind, sym->type);
		sym64->st_shndx = shndx;

	} else {
		hinternal();
		sym32 = &(entry->sym32);

		switch(sym->type) {
		case SYMBOL_FUNCTION:
			// its starting offset it is already been evaluated in a previous pass
			shndx = text[sym->version]->index;	// TODO_: it must be updated in order to support multiple .text sections
			break;

		case SYMBOL_VARIABLE:
			// verify if the object has to be binded to the COMMON section,
			// that is the variable is not allocated yet; otherwise .data section
			// must be filled up with the relative content
			if(sym->secnum != SHN_COMMON) {
				sym->offset = elf_write_data(sec, sym->payload, sym->size);
				shndx = sec->index;	// TODO_: it must be updated in order to support multiple .data sections
			}
			break;

		case SYMBOL_SECTION:
			//sym->extra_flags = ELF32_ST_INFO(STB_LOCAL, STT_SECTION);
			sym->bind = STB_LOCAL;
			sym->type = STT_SECTION;
			break;

		case SYMBOL_FILE:
			//sym->extra_flags = ELF32_ST_INFO(STB_LOCAL, STT_FILE);
			sym->bind = STB_LOCAL;
			sym->type = STT_FILE;
			shndx = SHN_ABS;
			break;

		case SYMBOL_UNDEF:
		default:
			// since they are undefined, it is not possible to infer local or global binding
			// must be used, hence only the type will be updated leaving the bind unaltered
			//sym->extra_flags += ELF32_ST_TYPE(STT_NOTYPE);
			sym->type = STT_NOTYPE;
			shndx = SHN_UNDEF;
		}

		// write the symbol name into the string_table and get the offset to store in st_name
		sym32->st_name = elf_write_string(strtable, (char *)sym->name);
		sym32->st_value = sym->offset;
		sym32->st_size = sym->size;
		sym32->st_info = ELF32_ST_INFO(sym->bind, sym->type);
		sym32->st_shndx = shndx;
	}

	// Check if section must be enlarged
	check_section_size(symtable, size);

	// Copy ELF symbol's meta-data into the symbol table
	memcpy(symtable->ptr, entry, size);

	ptr = symtable->ptr;
	sym->offset = ((char *)ptr - (char *)symtable->payload);
	symtable->ptr = (void *)((char *)symtable->ptr + size);

	hnotice(3, "Symbol [%u] '%s' (type %d and bind %d) of %d bytes written into section %s at offset <%#08llx>\n", sym->index, sym->name,
			sym->type, sym->bind, sym->size, sec ? sec->name : "(none)", sym->offset);

	return sym->index;
}


/**
 * Writes a the function code passed into the section specified.
 *
 * @param sec Section descriptor to which write the function's code
 * @param func Descriptor of the function that have to be written
 *
 * @return The function's offset from the beginning of the section
 */
unsigned long elf_write_code(section *sec, function *func) {
	insn_info *instr;
	insn_info_x86 *x86;

	int machine;

	unsigned long long old_offset, offset, addr, written;

	size_t size;

	void *ptr;

	ll_node *rela_node;
	symbol *rela;

	int displ;

	// Compute function size
	size = 0;
	for (instr = func->begin_insn; instr; instr = instr->next) {
		size += instr->size;
	}

	// Needed because otherwise relocations entries are doubled
	sec->reference = 0;

	// Check if section must be enlarged
	check_section_size(sec, size);

	// Save the current content pointer in order to get the starting offset
	// from which the function begins in the new '.text.xyz' section
	offset = (unsigned long)((char *)sec->ptr - (char *)sec->payload);
	written = 0;

	// Get machine information
	machine = ELF(is64) ? ELF(hdr)->header64.e_machine : ELF(hdr)->header32.e_machine;

	if (machine == -1) {
		herror(true, "Instruction code not yet implemented...\n");
	}

	ptr = sec->ptr;

	for (instr = func->begin_insn; instr; instr = instr->next) {
		displ = 0;

		switch(machine) {
			case EM_X86_64:
				x86 = &instr->i.x86;

				if (x86->disp != 0) {
					displ = x86->disp_size;
				}
				break;
			default:
				herror(true, "Architecture type not recognized!\n");
		}

		// old_offset = instr->new_addr;
		// instr->new_addr = offset + written;

		// Write instruction
		memcpy(sec->ptr, x86->insn, instr->size);

		sec->ptr = (void *)((char *)sec->ptr + instr->size);
		// written += instr->size;

		// For each relocation that apply to this instruction we have to rewrite them
		// Write relocations within instruction
		for (rela_node = instr->reference.first; rela_node; rela_node = rela_node->next) {
			rela = rela_node->elem;
			rela->relocation.sec = text[PROGRAM(version)];

			// hprint("Offset: %08llx, Orig: %08llx + %ld, New: %08llx + %ld\n",
			// 	rela->relocation.offset, old_offset, rela->relocation.offset - old_offset, instr->new_addr, rela->relocation.offset - old_offset);

			// addr = instr->new_addr + instr->opcode_size + displ;
			// // addr = instr->new_addr + (rela->relocation.offset - old_offset);
			addr = rela->relocation.offset;

			elf_write_reloc(rela_text[PROGRAM(version)], rela, addr, rela->relocation.addend);
		}
	}

	// func->symbol->size = written;

	hnotice(3, "Function '%s' has been written at '%s' + %u with size %u\n",
		func->name, sec->name, func->symbol->offset, func->symbol->size);

	// FIXME: non sono sicuro che l'offset sia gestito correttamente
	return offset;
}


/**
 * Writes a rela entry into the section passed.
 * Provided the rela section, the symbol and the relocation address (offset),
 * it builds the rela entry to be stored.
 *
 * @param sec Pointer to the section descriptor
 * @param index Is the symbol index within the symtab section, to which the relocation refers
 * @param addr The explicit address to which apply the relocation
 * @param addend Explicit addend to write in the RELA entry
 *
 * @return The offset within the destination section to which the relocation applies
 */
long elf_write_reloc(section *sec, symbol *sym, unsigned long long addr, long addend) {
	Section_Hdr *hdr;
	Elf_Rela *rela;

	size_t size;

	if (sec == NULL) {
		herror(false, "A relocation entry was not added: target section seems that do not exist!\n");
	}

	if (sym->version < 0) {
		herror(false, "Symbol '%s' [%d] against which the relocation applies has been skipped: semantic correctness cannot be ensured!\n",
			sym->name, sym->index);
	}

	// hnotice(3, "Relocation [%d] at '%s' + %0llx to symbol '%s' + %d has to be applied\n",
	// 	sym->relocation.type, sym->relocation.sec->name, sym->relocation.offset, sym->name, sym->relocation.addend);

	size = rela_size();
	hdr = (Section_Hdr *) sec->header;
	rela = (Elf_Rela *) calloc(size, 1);

	// No 'reloc_info' macro was used since it needed to add
	// specific information to each of the different field
	// TODO: how to recalculate the relocation type?
	if(ELF(is64)) {
		rela->rel64.r_info = ELF64_R_INFO(sym->index, sym->relocation.type);
		rela->rel64.r_offset = addr;
		// rela->rel64.r_offset = sym->relocation.offset;
		rela->rel64.r_addend = addend;
	} else {
		rela->rel32.r_info = ELF32_R_INFO(sym->index, sym->relocation.type);
		rela->rel32.r_offset = addr;
		// rela->rel32.r_offset = sym->relocation.offset;
		rela->rel32.r_addend = addend;
	}

	// Check if section must be enlarged
	check_section_size(sec, size);

	memcpy(sec->ptr, rela, sizeof(Elf_Rela));

	sec->ptr = (void *)((char *)sec->ptr + sizeof(Elf_Rela));

	// Marks the symbol as unreferenced, since it is resolved.
	// This way, we prevent that subsequent parsing will create
	// the same entries.
	// sym->referenced = 0;

	hnotice(4, "Written relocation entry at offset <%#08llx> to symbol '%s' (%d) %ld\n",
		addr, sym->name, sym->index, addend);

	return addr;
}


/**
 * Creates a new empty section descriptor with its header.
 * Through the section it is possible to invoke API function to handle the
 * output ELF file.
 *
 * @param sec Pointer to the new section descriptor
 * @param type Section type, constant (SHT_xyz)
 * @param size Optional parameter to specify the exact size of the section.
 * If it is not provided, automatic resizing will be used when necessary.
 * @param flags ELF's flags attribute of the section
 *
 * @return The address of the new section descriptor
 */
static section* elf_create_section(int type, int size, int flags) {
	section *s, *sec;

	Section_Hdr *hdr;
	Elf64_Shdr *hdr64;
	Elf32_Shdr *hdr32;

	size_t shsize, idx;

	shsize = shdr_size();
	hdr = calloc(shsize, 1);
	sec = calloc(sizeof(section), 1);

	sec->header = hdr;
	idx = 0;

	if (ELF(is64)) {
		hdr64 = &(hdr->section64);

		// Increment the number of all sections if a new one is created
		idx = hijacked.ehdr->header64.e_shnum++;

		//	hdr64->sh_name = elf_write_string(shstrtab, name);
		hdr64->sh_type = type;
		hdr64->sh_flags = flags;

		// if section's size is provide set it to its header
		// otherwise the implicit automatic resizing mechanism is used
		hdr64->sh_size = size;

	} else {
		hdr32 = &(hdr->section32);

		// Increment the number of all sections if a new one is created
		idx = hijacked.ehdr->header32.e_shnum++;

		//	hdr32->sh_name = elf_write_string(shstrtab, name);
		hdr32->sh_type = type;
		hdr32->sh_flags = flags;

		// if section's size is provide set it to its header
		// otherwise the implicit automatic resizing mechanism is used
		hdr32->sh_size = size;
	}

	sec->index = idx;
	sec->type = type;

	hnotice(3, "Section of type %d of %d bytes created with index %d\n",
		sec->type, size, sec->index);

	// links created sections together
	if (hijacked.sections == NULL) {
		hijacked.sections = sec;
	}
	else {
		s = hijacked.sections;
		while(s->next) {
			s = s->next;
		}

		s->next = sec;
	}

	return sec;
}


/**
 * Give a name to the section.
 * Provided a section, gives a name to it. Automatically the offset
 * from which the name begins, will be updated into the relative
 * section's header.
 *
 * @param sec Section descriptor to which set the name
 * @param name The buffer containing the section's name
 */
inline static void elf_name_section(section *sec, char *name) {
	Section_Hdr *hdr;
	Elf64_Shdr *hdr64;
	Elf32_Shdr *hdr32;

	sec->name = malloc(sizeof(char) * (strlen(name) + 1));
	if(!sec->name) {
		herror(true, "Out of memory!\n");
	}
	strcpy((char *)sec->name, name);

	hdr = sec->header;
	if(ELF(is64)) {
		hdr64 = &(hdr->section64);
		hdr64->sh_name = elf_write_string(shstrtab, name);
	} else {
		hdr32 = &(hdr->section32);
		hdr32->sh_name = elf_write_string(shstrtab, name);
	}
}


/**
 * Copy the given section to the ELF output file.
 * It writes down the given section and its header to the new ELF. It assumes that
 * the position of the stream's file pointer is correct. Further the section must have been
 * previously trimmed to the exact size before invoke this function, otherwise some data
 * will be overwritten.
 *
 * @param file Is the Stream file descriptor to which write the section passed
 * @param sec Is the pointer to the section descriptor to write
 *
 * @return Returns the starting section's offset from the beginning of file
 */
inline static long elf_write_section(FILE *file, section *sec) {
	Section_Hdr *hdr;
	long offset;

	hdr = sec->header;
	offset = ftell(file);
	fwrite(sec->payload, header_info(hdr, sh_size), 1, file);

	hnotice(3, "Section '%s' [%d] copied (%lu bytes) starting from <%#08lx>\n",
		sec->name, sec->index, header_info(hdr, sh_size), offset);

	return offset;
}


/**
 * Write a section header into the output file file.
 *
 * @param file Output file descriptor
 * @param sec Section descriptor to which the header is relative to
 *
 * @return The offset from which the section header is written
 */
inline static long elf_write_section_header(FILE *file, section *sec) {
	long offset;
	int shsize;

	shsize = shdr_size();

	offset = ftell(file);
	fwrite(sec->header, shsize, 1, file);

	hnotice(3, "Section header copied (%u bytes) at offset <%#08lx>\n", shsize, offset);

	return offset;
}


static void elf_build(void) {
	size_t size;

	unsigned int ver;

	unsigned char secname[SECNAME_SIZE];

	unsigned int targetndx;
	symbol *sym;
	// symbol *prev, *sym2;

	function *func;

	section *rela;
	section *sec;


	hnotice(3, "Allocating sections memory\n");

	// Allocate in-memory space for the hijacked ELF's header
	hijacked.ehdr = calloc(ehdr_size(), 1);

	// ------------------------------------------------------
	// META SECTIONS
	// ------------------------------------------------------

	// Create the null section
	elf_create_section(SHT_NULL, 0, 0);

	// Create the shared string table
	shstrtab = elf_create_section(SHT_STRTAB, 0, 0);
	elf_name_section(shstrtab, ".shstrtab");
	elf_write_string(shstrtab, "");

	// Create the local string table
	strtab = elf_create_section(SHT_STRTAB, 0, 0);
	elf_name_section(strtab, ".strtab");
	elf_write_string(strtab, "");

	// Create symbol table
	// size = 0;

	// for (sym = PROGRAM(symbols); sym; sym = sym->next) {
	// 	if (sym->duplicate == false) {
	// 		size += sym_size();
	// 	}
	// }

	symtab = elf_create_section(SHT_SYMTAB, 0, 0);
	elf_name_section(symtab, ".symtab");

	set_hdr_info(symtab->header, sh_entsize, sym_size());
	set_hdr_info(symtab->header, sh_link, strtab->index);

	// sym = (symbol *) malloc(sizeof(symbol));
	// bzero(sym, sizeof(symbol));

	// ------------------------------------------------------
	// DATA SECTIONS
	// ------------------------------------------------------

	sym = find_symbol_by_name(".rodata");

	if (sym) {
		rodata = elf_create_section(SHT_PROGBITS, 0, SHF_ALLOC);
		elf_name_section(rodata, ".rodata");

		set_hdr_info(rodata->header, sh_addralign,
			header_info(((Section_Hdr *) sym->sec->header), sh_addralign));
	}

	sym = find_symbol_by_name(".data");

	if (sym) {
		data = elf_create_section(SHT_PROGBITS, 0, SHF_ALLOC|SHF_WRITE);
		elf_name_section(data, ".data");

		set_hdr_info(data->header, sh_addralign,
			header_info(((Section_Hdr *) sym->sec->header), sh_addralign));
	}

	sym = find_symbol_by_name(".bss");

	if (sym) {
		bss = elf_create_section(SHT_NOBITS, 0, SHF_ALLOC|SHF_WRITE);
		elf_name_section(bss, ".bss");

		set_hdr_info(bss->header, sh_addralign,
			header_info(((Section_Hdr *) sym->sec->header), sh_addralign));
	}

	sym = find_symbol_by_name(".tdata");

	if (sym) {
		tdata = elf_create_section(SHT_PROGBITS, 0, SHF_ALLOC|SHF_WRITE|SHF_TLS);
		elf_name_section(tdata, ".tdata");

		set_hdr_info(tdata->header, sh_addralign,
			header_info(((Section_Hdr *) sym->sec->header), sh_addralign));
	}

	sym = find_symbol_by_name(".tbss");

	if (sym) {
		tbss = elf_create_section(SHT_NOBITS, 0, SHF_ALLOC|SHF_WRITE|SHF_TLS);
		elf_name_section(tbss, ".tbss");

		set_hdr_info(tbss->header, sh_addralign,
			header_info(((Section_Hdr *) sym->sec->header), sh_addralign));
	}

	// [SE] Hackish...
	// sym = find_symbol(".tbss");

	// if (sym) {
	// 	section *tbss_orig = find_section_by_name(".tbss");

	// 	tbss = elf_create_section(SHT_NOBITS, sym->size, SHF_ALLOC|SHF_WRITE|SHF_TLS);
	// 	elf_name_section(tbss, ".tbss");
	// 	tbss->type = SECTION_TLS;

	// 	set_hdr_info(tbss->header, sh_addralign,
	// 		header_info(((Section_Hdr *) tbss_orig->header), sh_addralign));

	// 	for (sym = PROGRAM(symbols); sym; sym = sym->next) {
	// 		if (sym->secnum == tbss_orig->index) {
	// 			sym->secnum = tbss->index;
	// 		}
	// 	}
	// }

	// sym = find_symbol(".tdata");

	// if (sym) {
	// 	section *tdata_orig = find_section_by_name(".tdata");

	// 	tdata = elf_create_section(SHT_PROGBITS, sym->size, SHF_ALLOC|SHF_WRITE|SHF_TLS);
	// 	elf_name_section(tdata, ".tdata");
	// 	tdata->type = SECTION_TLS;

	// 	set_hdr_info(tdata->header, sh_addralign,
	// 		header_info(((Section_Hdr *) tdata_orig->header), sh_addralign));
	// }
	// [/SE]

	// ------------------------------------------------------
	// NON RELA-TEXT SECTIONS
	// ------------------------------------------------------

	for (sec = PROGRAM(sections)[0]; sec; sec = sec->next) {

		if (sec->type == SECTION_RELOC) {
			targetndx = sec_field(sec->index, sh_info);

			if (str_prefix(sec_name(targetndx), ".text")) {
				continue;
			}

			rela = elf_create_section(SHT_RELA, 0, 0);

			set_hdr_info(rela->header, sh_entsize, rela_size());
			set_hdr_info(rela->header, sh_link, symtab->index);

			if (str_equal(sec_name(targetndx), ".data")) {
				set_hdr_info(rela->header, sh_info, data->index);
				elf_name_section(rela, sec_name(sec->index));

				rela_data = rela;
			}
			else if(str_equal(sec_name(targetndx), ".rodata")) {
				set_hdr_info(rela->header, sh_info, rodata->index);
				elf_name_section(rela, sec_name(sec->index));

				rela_rodata = rela;
			}
		}

	}

	// ------------------------------------------------------
	// TEXT/RELA-TEXT SECTIONS
	// ------------------------------------------------------

	for (ver = 0; ver < PROGRAM(versions); ver++) {
		switch_executable_version(ver);

		// Count the number of the registered functions and create a
		// new text section with the right dimension
		size = 0;

		for (func = PROGRAM(v_code)[ver]; func; func = func->next) {
			size += func->symbol->size;
		}

		// Creates as much .text sections as the instrumentation versions
		text[ver] = elf_create_section(SHT_PROGBITS, size, SHF_EXECINSTR|SHF_ALLOC);

		bzero(secname, sizeof(secname));
		strcpy(secname, ".text");

		if (config.rules[ver]->suffix) {
			strcat(secname, ".");
			strcat(secname, (const char *)config.rules[ver]->suffix);
		}

		elf_name_section(text[ver], secname);

		// Create as much .rela.text relocation sections as the instrumentation versions
		rela_text[ver] = rela = elf_create_section(SHT_RELA, 0, 0);

		set_hdr_info(rela->header, sh_entsize, rela_size());
		set_hdr_info(rela->header, sh_link, symtab->index);
		set_hdr_info(rela->header, sh_info, text[ver]->index);

		rela->reference = 0;

		bzero(secname, sizeof(secname));
		strcpy(secname, ".rela.text");

		if (config.rules[ver]->suffix) {
			strcat(secname, ".");
			strcat(secname, (const char *)config.rules[ver]->suffix);
		}

		elf_name_section(rela, secname);
	}

	hsuccess();
}


/**
 * Build the header of the ELF file.
 */
static void elf_build_eheader(void) {
	Elf_Hdr *ehdr;
	Elf64_Ehdr *ehdr64;
	Elf32_Ehdr *ehdr32;
	unsigned char *eident;
	int ehsize;

	hnotice(3, "Initializing ELF header...\n");

	// Initialize the new elf's header descriptor
	// ehsize = ehdr_size();
	// hijacked.ehdr = (Elf_Hdr *) malloc(ehsize);
	// bzero(hijacked.ehdr, ehsize);

	ehdr = hijacked.ehdr;
	eident = ehdr_info(ehdr, e_ident);

	// Setting up ELF identification
	eident[EI_MAG0] = ELFMAG0;
	eident[EI_MAG1] = ELFMAG1;
	eident[EI_MAG2] = ELFMAG2;
	eident[EI_MAG3] = ELFMAG3;
	eident[EI_CLASS] = ELF(is64) ? ELFCLASS64 : ELFCLASS32;
	eident[EI_VERSION] = EV_CURRENT;
	eident[EI_DATA] = ((char) 0x00ff) != 0 ? ELFDATA2LSB : ELFDATA2MSB;

	// TODO: e_machine and e_flags
	if (ELF(is64)) {
		ehdr64 = &(ehdr->header64);

		ehdr64->e_type = ET_REL;
		ehdr64->e_machine = EM_X86_64;
		ehdr64->e_version = EV_CURRENT;
		ehdr64->e_ehsize = ehdr_size();
		ehdr64->e_shentsize = shdr_size();
		ehdr64->e_shstrndx = shstrtab->index;
	} else {
		ehdr32 = &(ehdr->header32);

		ehdr32->e_type = ET_REL;
		ehdr32->e_machine = EM_X86_64;
		ehdr32->e_version = EV_CURRENT;
		ehdr32->e_ehsize = ehdr_size();
		ehdr32->e_shentsize = shdr_size();
		ehdr32->e_shstrndx = shstrtab->index;
	}

	hsuccess();
}



static void elf_update_symbol_list(symbol *first) {
	symbol *sym, *prev;
	section *sec;

	size_t idx, local;

	idx = local = 0;

	hnotice(2, "Update list of symbol to be written\n");

	// Iterate all over the symbols to purge symbols that do not hold
	// anymore in the new generated code

	sym = first;
	while(sym) {

		// Check if the symbol is already present in the section and, in that case,
		// skip it because it is probably a relocation

		if (sym->authentic == false) {
			sym->index = idx - 1;
			prev = sym;
			sym = sym->next;

			continue;
		}

		// Skip old section and file symbols
		// warning! relocation could be applied to these symbols
		// hence is mandatory to update the insn->reference field
		// accordingly, in such a case

		if (sym->type == SYMBOL_FILE) {
			// sym->name = (unsigned char *)hijacked.path;
		}

		else if(sym->type == SYMBOL_SECTION) {
			hnotice(4, "Look for the section symbol name '%s' in the new section list...\n",
				sym->name);

			// Check if the section will be present in the output object file
			// (we skip the NULL section because it doesn't have a name)

			for (sec = hijacked.sections->next; sec; sec = sec->next) {
				if(str_equal(sym->name, sec->name)) {
					sym->sec = sec;
					sym->secnum = sec->index;
					// sec = sec->next;

					// sym->size = 0;

					hnotice(4, "Updated the section symbol index for '%s' to %d\n",
						sym->name, sym->secnum);
					break;
				}
			}

			if (sec == NULL) {
				// No section is found, so we skip it...

				// TODO: da abilitare un supporto dinamico per il multitext
				// if(1) {
				// 	// se è stata richiesta la creazione di tutte le sezioni originali
				// 	// allora viene creata una nuova sezione a partire dal file originale

				// 	sec = PROGRAM(sections);
				// 	while(sec) {
				// 		if(!strcmp(sym->name, (char *)sec->name)) {

				// 			elf_create_section(sec->type, sec->size, sec->flags);
				// 			sym->secnum = sec->index;
				// 			//sym->index = sec->index;
				// 			sec = sec->next;

				// 			hnotice(4, "Updated the section symbol index to %d\n", sym->secnum);
				// 			break;
				// 		}

				// 		sec = sec->next;
				// 	}
				// }

				hnotice(4, "Section '%s' will be ignored\n", sym->name);

				sym->version = -1;

				prev->next = sym->next;
				sym = prev->next;

				continue;
			}
		}

		sym->index = idx;

		hnotice(3, "Letting through symbol '%s' [%d] in '%s' of type %s (%s)\n",
			sym->name, sym->index, sym->sec ? sym->sec->name : "(none)",
				symbol_type_str[sym->type], symbol_bind_str[sym->bind]);

		if (sym->bind == STB_LOCAL) {
			local += 1;
		}

		idx += 1;
		prev = sym;
		sym = sym->next;
	}

	// Update the symbol table header with the total number of
	// local symbols that will be output
	set_hdr_info(symtab->header, sh_info, local);

	hnotice(3, "%d total symbols registered (%d are local)\n", idx, local);
}


static void elf_fill_sections(void) {
	size_t ver;

	symbol *sym;
	function *func;
	section *sec;

	unsigned long long offset;
	size_t size;

	void *content;

	// ------------------------------------------------------
	// TEXT/RELA-TEXT SECTIONS
	// ------------------------------------------------------
	hnotice(2, "Fill text...\n");

	offset = 0;

	for (ver = 0; ver < PROGRAM(versions); ver++) {
		switch_executable_version(ver);

		update_instruction_addresses(ver);
		update_jump_displacements(ver);

		// Even if functions belong to different '.text' original sections,
		// they are all actually written into the same output text section
		for (func = PROGRAM(v_code)[PROGRAM(version)]; func; func = func->next) {
			// hnotice(3, "Writing function '%s' (%d bytes) on section '%s' (version %d)\n",
			// 	func->name, func->symbol->size, text[func->symbol->version]->name, func->symbol->version);

			offset = elf_write_code(text[func->symbol->version], func);

			// Update the symbol offset in the new '.text' section as well as
			// its size...
			func->symbol->offset = offset;
		}
	}

	// ------------------------------------------------------
	// META SECTIONS
	// ------------------------------------------------------

	hnotice(2, "Fill symtab...\n");

	for (sym = PROGRAM(symbols); sym; sym = sym->next) {
		// Skip symbol duplicates, since they are only used for relocation purposes
		if (sym->authentic == false) {
			continue;
		}

		sym->index = elf_write_symbol(symtab, sym, strtab);
	}

	// ------------------------------------------------------
	// DATA SECTIONS
	// ------------------------------------------------------

	hnotice(2, "Fill rodata data sections...\n");
	offset = 0;

	for (sec = PROGRAM(sections)[0]; sec; sec = sec->next) {
		sym = sec->sym;

		if (sym == NULL) {
			// Could be a .rela.xyz section, anyway it's not of interest
			continue;
		}

		if (str_equal(sec->name, ".data")) {
			size = sym->size;

			hnotice(3, "Copying raw data of section '%s' [%d] (%d bytes)\n",
				sec->name, sym->secnum, size);

			content = calloc(size, 1);

			// This is to handle the case that hijacker will adds data to
			// pre-existent sections (e.g., in case of switch cases for
			// different versions)
			memcpy(content, sec->payload, sec_size(sec->index));
			elf_write_data(data, content, size);
		}

		else if (str_equal(sec->name, ".rodata")) {
			size = sym->size;

			hnotice(3, "Copying raw data of section '%s' [%d] (%d bytes)\n",
				sec->name, sym->secnum, size);

			content = calloc(size, 1);

			// This is to handle the case that hijacker will adds indirectly data to pre-existent sections
			// i.e. in case of switch cases for different versions
			memcpy(content, sec->payload, sec_size(sec->index));
			elf_write_data(rodata, content, size);
		}

		else if (str_equal(sec->name, ".bss")) {
			hnotice(3, "Setting size of section '%s' [%d] (%d bytes)\n",
				sec->name, sym->secnum, sym->size);

			set_hdr_info(bss->header, sh_size, sym->size);
			// elf_write_data(bss, sec->payload, sym->size);
		}

		else if (str_equal(sec->name, ".tbss")) {
			hnotice(3, "Setting size of section '%s' [%d] (%d bytes)\n",
				sec->name, sym->secnum, sym->size);

			set_hdr_info(tbss->header, sh_size, sym->size);
			// elf_write_data(tbss, sec->payload, sym->size);
		}
	}

	// ------------------------------------------------------
	// RELOC SECTIONS
	// ------------------------------------------------------

	hnotice(2, "Writing remaining relocation entries...\n");
	// SECTION->TEXT relocations have been already installed while
	// populating the new '.text.xyz' section. As a result, we only
	// need to deal with SECTION->SECTION relocations

	for (sym = PROGRAM(symbols); sym; sym = sym->next) {
		if (sym->authentic) {
			continue;
		}

		/* if (str_prefix(sym->relocation.sec->name, ".text")) {
			sec = rela_text[sym->version];
		}
		else */
		if (str_prefix(sym->relocation.sec->name, ".rodata")) {
			sec = rela_rodata;
		}
		else if (str_prefix(sym->relocation.sec->name, ".data")) {
			sec = rela_data;
		}
		else if (str_prefix(sym->relocation.sec->name, ".tdata")) {
			hinternal();
			// sec = rela_tdata;
		}
		else {
			// herror(true, "Relocation to symbol '%s' has specified a non-valid section (%s): ignored\n",
			// 	sym->name, sec->name);
			continue;
		}

		// Needed because of multiple '.text' input sections
		if (str_prefix(sym->name, ".text") && sym->relocation.target_insn) {
			offset = sym->relocation.target_insn->new_addr;
		}

		elf_write_reloc(sec, sym, sym->relocation.offset, offset);
	}
}


/**
 * Generates the new object file.
 */
void elf_generate_file(char *path) {
	FILE *file;
	section *sec;

	size_t shnum;
	unsigned long offset;

	hnotice(1, "Initializing the new ELF file...\n");

	elf_build();
	elf_build_eheader();

	// Open the output file and write the content
	hnotice(1, "Creating a new output file...\n");

	// If the output path is not valid, the standard one is used
	if (!path) {
		path = malloc(strlen(DEFAULT_OUT_NAME) + 1);
		strcpy(path, DEFAULT_OUT_NAME);
	}

	file = fopen(path, "w+");
	if (!file) {
		herror("Unable to write output ELF file '%s'!\n", path);
	}

	hijacked.path = malloc(strlen(path) + 1);
	strcpy(hijacked.path, path);

	// Reserve space for the ELF's header (written later)
	fseek(file, ehdr_size(), SEEK_SET);

	// update symbol references and indexes
	elf_update_symbol_list(PROGRAM(symbols));

	// Fill output sections with their respective contents
	elf_fill_sections();

	// Write all sections to file
	hnotice(2, "Writing sections content...\n");
	shnum = 0;

	for (sec = hijacked.sections; sec; sec = sec->next) {
		// We shrink the size of each section to the appropriate size
		shrink_section_size(sec);

		// We set additional information depending on the section type
		if (sec->type == SECTION_SYMBOLS) {
			set_hdr_info(sec->header, sh_addralign, sym_size());
			// set_hdr_info(sec->header, sh_addralign, 8);
		}
		// else if (sec->type != SECTION_TLS) {
		// 	set_hdr_info(sec->header, sh_addralign, 1);
		// }

		offset = elf_write_section(file, sec);
		set_hdr_info(sec->header, sh_offset, offset);

		shnum += 1;
	}

	// At this point we know how much sections are in the object and we can
	// insert this piece of information into the ELF's header.
	set_elfhdr_info(hijacked.ehdr, e_shnum, shnum);

	// Additionally, the current file pointer represents the starting offset
	// from which sections' headers begin.
	offset = ftell(file);
	set_elfhdr_info(hijacked.ehdr, e_shoff, offset);

	// Write sections' headers
	hnotice(2, "Writing sections' headers...\n");
	hnotice(3, "Section headers starting from offset <%#08lx>\n", offset);

	for (sec = hijacked.sections; sec; sec = sec->next) {
		offset = elf_write_section_header(file, sec);
	}

	// We can now write the ELF's header
	hnotice(2, "Writing the ELF's header...\n");

	rewind(file);
	fwrite(hijacked.ehdr, ehdr_size(), 1, file);
	fclose(file);
}
