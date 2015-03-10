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
#include <unistd.h>

#include <hijacker.h>
#include <utils.h>
#include <prints.h>
#include <executable.h>

#include "elf-defs.h"
#include "handle-elf.h"
#include "emit-elf.h"
#include <x86/emit-x86.h>

#define SECTION_INIT_SIZE 1024

hijacked_elf hijacked;		/// Hijacked output ELF descriptor

// XXX: hanno gli stessi nomi di altre variabili globali, e` corretto?
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


/**
 * Check if the section has enough available space.
 * If the section could not sustain the required space, than
 * automatically it will be double its size.
 *
 * @param sec Section descriptor
 * @param span Integer representing the size to be written
 */
inline static void check_section_size(section *sec, int span) {
	Section_Hdr *hdr;
	unsigned long long offset;
	unsigned long long size = 0;


	hdr = (Section_Hdr *) sec->header;

	offset = ((char *)sec->ptr - (char *)sec->payload);
	size = header_info(hdr, sh_size);

	hnotice(6, "Check if section '%s' (index %u) has enough available space (Available = %llu, Needed = %d, Offset = %llu)\n",
		sec->name, sec->index, (size - offset), span, offset);

	if(size == 0)
		size = SECTION_INIT_SIZE;

	if(sec->ptr == NULL) {
		sec->ptr = sec->payload = malloc(size);
		hnotice(6, "Allocated %llu bytes for section %u\n", size, sec->index);
	} else if (((char *)sec->ptr + span) >= ((char *)sec->payload + size)) {
		size *= 2;
		sec->ptr = sec->payload = realloc(sec->payload, size);
		sec->ptr = (void *)((char *)sec->ptr + offset);		// Replace 'ptr' to the original displacement in the newly allocated block
		hnotice(6, "Doubling size of section %u to %llu...\n", sec->index, size);
	}

	// update the size into the section header
	set_hdr_info(hdr, sh_size, size);
}


/**
 * Given a section it shrinks its size to the exact one
 *
 * @param sec Section descriptor
 * @return Returns the final size in bytes
 */
inline static long shrink_section_size(section *sec) {
	long size;
	long old_size;
	Section_Hdr *hdr;

	hdr = sec->header;
	size = ((char *)sec->ptr - (char *)sec->payload);

	if(size < 0)
		hinternal();

	sec->payload = realloc(sec->payload, size);

	old_size = header_info(hdr, sh_size);
	set_hdr_info(hdr, sh_size, size);

	hnotice(3, "Section '%s' [%d] size shrink from %lld to %lld bytes\n", sec->name, sec->index, old_size, size);

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

	if(buffer == NULL)
		return 0;

	hdr = (Section_Hdr *) sec->header;
	buflen = strlen(buffer) + 1;		// takes into account string terminator '\0'

	// check if section size must be enlarged
	check_section_size(sec, buflen);

	// copy buffer in the section payload
	strcpy(sec->ptr, buffer);

	// save the old pointer to the newly written section area
	// and update the main section's payload pointer
	ptr = sec->ptr;
	sec->ptr = (void *)((char *)sec->ptr + buflen);

	hnotice(4, "String written to .strtab section at offset <%#08lx> :: '%s'\n", ((char *)ptr - (char *)sec->payload), buffer);

	return (long)((char *)ptr - (char *)sec->payload);
}


/**
 * Writes a new data entry in the data section
 *
 * @param sec Data section to which write the entry
 * @param data Pointer to the buffer containing the data to be written
 * @param size Size of the buffer data to copy into the section
 *
 * @return The offset of the data written from section's beginning
 */
long elf_write_rodata(section *sec, void *buffer, int size) {
	Section_Hdr *hdr;
	void *ptr;

	// check if section must be enlarged
	check_section_size(sec, size);

	hdr = (Section_Hdr *) sec->header;

	memcpy(sec->ptr, buffer, size);
	ptr = sec->ptr;
	sec->ptr = (void *)((char *)sec->ptr + size);

	hnotice(3, "Read-only data written into section '%s' [%d] at offset <%#08lx>\n", sec->name, sec->index, ((char *)ptr - (char *)sec->payload));
	hdump(4, "Data buffer dump", buffer, size);

	return (long)((char *)ptr - (char *)sec->payload);
}


/**
 * Writes a new data entry in the data section
 *
 * @param sec Data section to which write the entry
 * @param data Pointer to the buffer containing the data to be written
 * @param size Size of the buffer data to copy into the section
 *
 * @return The offset of the data written from section's beginning
 */
long elf_write_data(section *sec, void *buffer, int size) {
	Section_Hdr *hdr;
	void *ptr;

	// check if section must be enlarged
	check_section_size(sec, size);

	hdr = (Section_Hdr *) sec->header;

	memcpy(sec->ptr, buffer, size);
	ptr = sec->ptr;
	sec->ptr = (void *)((char *)sec->ptr + size);

	hnotice(3, "Data written into section '%s' [%d] at offset <%#08lx>\n", sec->name, sec->index, ((char *)ptr - (char *)sec->payload));
	hdump(4, "Data buffer dump", buffer, size);

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
 * @param data Data section's descriptor to which store the symbol's initial value
 *
 * @return Symbol index within the symbol table of the written entry
 */
int elf_write_symbol(section *symbol_table, symbol *sym, section *string_table, section *data_sec) {
	static int idx = 0;
	Elf_Sym *entry;
	Elf64_Sym *sym64;
	Elf32_Sym *sym32;
	Section_Hdr *hdr;
	int size;
	int shndx = 0;
	void *ptr;

	// build a new symbol entry accordingly to the ELF class
	size = sym_size();
	entry = (Elf_Sym *) malloc(size);
	shndx = sym->secnum;		// TODO: here?
	bzero(entry, size);

	//sym->index = idx++;

	hdr = (Section_Hdr *) symbol_table->header;

	if(ELF(is64)) {
		sym64 = &(entry->sym64);

		switch(sym->type) {
		case SYMBOL_FUNCTION:
			// its starting offset it is already been evaluated in a previous pass
			shndx = text[sym->version]->index;	// TODO: it must be updated in order to support multiple .text sections
			sym->initial = sym->position;
			break;

		case SYMBOL_VARIABLE:
			// verify if the object has to be binded to the COMMON section,
			// that is the variable is not allocated yet; otherwise .data section
			// must be filled up with the relative content
			if(sym->secnum != SHN_COMMON) {
				sym->position = elf_write_data(data_sec, &sym->position, sym->size);
				shndx = data_sec->index;	// TODO: it must be updated in order to support multiple .data sections
			}
			break;

		case SYMBOL_SECTION:
			// sections are always local symbols
			//sym->extra_flags = ELF64_ST_INFO(STB_LOCAL, STT_SECTION);
			sym->bind = STB_LOCAL;
			sym->type = STT_SECTION;
			break;

		case SYMBOL_FILE:
			// file symbols are always local
			//sym->extra_flags = ELF64_ST_INFO(STB_LOCAL, STT_FILE);
			sym->bind = STB_LOCAL;
			sym->type = STT_FILE;
			shndx = SHN_ABS;
			break;

		case SYMBOL_UNDEF:
		default:
			// since they are undefined, it is not possible to infer local or global binding
			// must be used, hence only the type will be updated leaving the bind unaltered
			//sym->extra_flags += ELF64_ST_TYPE(STT_NOTYPE);
			sym->type = STT_NOTYPE;
			shndx = SHN_UNDEF;
		}

		// write the symbol name into the string_table and get the offset to store in st_name
		sym64->st_name = elf_write_string(string_table, (char *)sym->name);
		sym64->st_value = sym->initial;
		sym64->st_size = sym->size;
		sym64->st_info = ELF64_ST_INFO(sym->bind, sym->type);
		sym64->st_shndx = shndx;

	} else {
		sym32 = &(entry->sym32);

		switch(sym->type) {
		case SYMBOL_FUNCTION:
			// its starting offset it is already been evaluated in a previous pass
			shndx = text[sym->version]->index;	// TODO: it must be updated in order to support multiple .text sections
			sym->initial = sym->position;
			break;

		case SYMBOL_VARIABLE:
			// verify if the object has to be binded to the COMMON section,
			// that is the variable is not allocated yet; otherwise .data section
			// must be filled up with the relative content
			if(sym->secnum != SHN_COMMON) {
				sym->position = elf_write_data(data_sec, &sym->position, sym->size);
				shndx = data_sec->index;	// TODO: it must be updated in order to support multiple .data sections
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
		sym32->st_name = elf_write_string(string_table, (char *)sym->name);
		sym32->st_value = sym->position;
		sym32->st_size = sym->size;
		sym32->st_info = ELF32_ST_INFO(sym->bind, sym->type);
		sym32->st_shndx = shndx;
	}

	// check if section must be enlarged
	check_section_size(symbol_table, size);

	// copy the information handled by symbol hjacker's descriptor into the elf's entry
	memcpy(symbol_table->ptr, entry, size);
	ptr = symbol_table->ptr;
	sym->position = ((char *)ptr - (char *)symbol_table->payload);
	symbol_table->ptr = (void *)((char *)symbol_table->ptr + size);

	hnotice(3, "Symbol [%u] '%s' (type %d and bind %d) of %d bytes written into section %u at offset <%#08llx>\n", sym->index, sym->name,
			sym->type, sym->bind, sym->size, symbol_table->index, sym->position);

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
	int machine;
	unsigned long offset;
	unsigned long written;
	unsigned long long total_size = 0;

	instr = func->insn;
	while(instr != NULL) {
		total_size += instr->size;
		instr = instr->next;
	}

	// otherwise relocations entries are doubled
	sec->reference = 0;

	check_section_size(sec, total_size);

	// save the current content pointer in order to have the
	// starting offset from which the function begins
	offset = (unsigned long)((char *)sec->ptr - (char *)sec->payload);
	written = 0;

	machine = ELF(is64) ? ELF(hdr)->header64.e_machine : ELF(hdr)->header32.e_machine;

	hnotice(3, "Writing function's data to text section...\n");

	switch (machine) {
	case -1:
		herror(true, "Instruction code not yet implemented...\n");
		break;

	case EM_X86_64:
		written += write_x86_code(func, sec, rela_text[PROGRAM(version)]);
		break;

	default:
		herror(true, "Architecture type not recognized!\n");
	}

	hnotice(3, "Function '%s' copied (%lu bytes) in section '%s'\n", func->name, written, sec->name);

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
	int size;

	// mhh, should not happen here, but...
	if(!sec) {
		herror(false, "A relocation entry was not added: target section seems that do not exist!\n");
		return -1; // TODO: is it correct to return -1 in case of error?
	}

	if(sym->version < 0) {
		herror(false, "Symbol '%s' [%d] against which the relocation applies has been skipped: semantic correctness cannot be ensured!\n",
			sym->name, sym->index);
	}

	size = rela_size();
	hdr = (Section_Hdr *) sec->header;
	rela = (Elf_Rela *) malloc(size);

	bzero(rela, sizeof(Elf_Rela));

	// no 'reloc_info' macro was used since it needed to add
	// specific information to each of the different field
	if(ELF(is64)) {
		// TODO: how to recalculate the relocation type

		rela->rel64.r_info = ELF64_R_INFO(sym->index, sym->relocation.type);
		rela->rel64.r_offset = addr;
		rela->rel64.r_addend = addend;
	} else {
		// TODO: how to recalculate the relocation type

		rela->rel32.r_info = ELF32_R_INFO(sym->index, sym->relocation.type);
		rela->rel32.r_offset = addr;
		rela->rel32.r_addend = addend;
	}

	check_section_size(sec, size);

	memcpy(sec->ptr, rela, sizeof(Elf_Rela));
	sec->ptr = (void *)((char *)sec->ptr + sizeof(Elf_Rela));

	// Marks the symbol as unreferenced, since it is resolved;
	// in this way we prevent that subsequent parsing will
	// create same entries
	sym->referenced = 0;

	hnotice(4, "Written relocation entry at offset <%#08llx> to symbol '%s' (%d) %ld\n", addr, sym->name, sym->index, addend);


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
	int shsize;
	int idx;

	shsize = shdr_size();
	hdr = malloc(shsize);
	bzero(hdr, shsize);

	sec = malloc(sizeof(section));
	bzero(sec, sizeof(section));

	sec->header = hdr;

	if(ELF(is64)) {
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

	hnotice(3, "Section of type %d of %d bytes created with index %d\n", sec->type, size, sec->index);

	// links created sections together
	if(hijacked.sections == NULL)
		hijacked.sections = sec;
	else {
		s = hijacked.sections;
		while(s->next)
			s = s->next;
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

	hnotice(3, "Section '%s' [%d] copied (%lu bytes) starting from <%#08lx>\n", sec->name, sec->index, header_info(hdr, sh_size), offset);

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
	ehsize = ehdr_size();
	hijacked.ehdr = (Elf_Hdr *) malloc(ehsize);
	bzero(hijacked.ehdr, ehsize);

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

	if(ELF(is64)) {
		ehdr64 = &(ehdr->header64);

		ehdr64->e_type = ET_REL;
		ehdr64->e_machine = EM_X86_64;	// TODO
		ehdr64->e_version = EV_CURRENT;
		// TODO: e_flags
		ehdr64->e_ehsize = ehdr_size();
		ehdr64->e_shentsize = shdr_size();
		ehdr64->e_shstrndx = shstrtab->index;
	} else {
		ehdr32 = &(ehdr->header32);

		ehdr32->e_type = ET_REL;
		ehdr32->e_machine = EM_X86_64;	// TODO
		ehdr32->e_version = EV_CURRENT;
		// TODO: e_flags
		ehdr32->e_ehsize = ehdr_size();
		ehdr32->e_shentsize = shdr_size();
		ehdr32->e_shstrndx = shstrtab->index;
	}

	hsuccess();
}


static void elf_build(void) {
	long size;
	unsigned int ver;
	unsigned int target;
	symbol *sym, *prev, *sym2;
	function *func;
	section *rela;
	section *sec;
	unsigned char secname[SECNAME_SIZE];

	hnotice(3, "Allocating sections memory\n");

	// build the descriptor for the output elf
	hijacked.ehdr = malloc(ehdr_size());

	// the very first section must be the null one
	elf_create_section(SHT_NULL, 0, 0);

	// then it is needed the sections' name string table
	shstrtab = elf_create_section(SHT_STRTAB, 0, 0);
	elf_write_string(shstrtab, "");
	elf_name_section(shstrtab, ".shstrtab");


	// start to build each standard section
	strtab = elf_create_section(SHT_STRTAB, 0, 0);
	elf_name_section(strtab, ".strtab");
	elf_write_string(strtab, "");

	// For each version a new .text section must be created
/*	for(ver = 0; ver < PROGRAM(versions); ver++) {
		switch_executable_version(ver);
		func = PROGRAM(code);

		// count the number of the registered functions and creates a
		// new section with the right dimension
		size = 0;
		while(func){
			size += func->symbol->size;
			func = func->next;
		}

		// Creates as much .text sections as the instrumentation versions
		text[ver] = elf_create_section(SHT_PROGBITS, size, SHF_EXECINSTR|SHF_ALLOC);

		bzero(secname, sizeof(secname));
		strcpy(secname, ".text");

		if(config.rules[ver]->suffix) {
			strcat(secname, ".");
			strcat(secname, (const char *)config.rules[ver]->suffix);
		}
		elf_name_section(text[ver], secname);
	}*/

	data = elf_create_section(SHT_PROGBITS, 0, SHF_ALLOC|SHF_WRITE);
	elf_name_section(data, ".data");

	bss = elf_create_section(SHT_NOBITS, 0, SHF_ALLOC|SHF_WRITE);
	elf_name_section(bss, ".bss");

	sym = find_symbol((unsigned char *)".rodata");
	rodata = elf_create_section(SHT_PROGBITS, size, SHF_ALLOC);
	elf_name_section(rodata, ".rodata");

	// count the number of the registered symbols and creates a
	// new section with the right dimension
	sym = PROGRAM(symbols);
	size = 0;
	prev = sym;
	while(sym) {
		/*// section and file symbols must be dropped in order to be reconstructed
			// with indexes of the new elf specification
			if(sym->type == SYMBOL_SECTION || sym->type == SYMBOL_FILE) {
				prev->next = sym->next;
				continue;
			}*/
		size += sym_size();
		sym = sym->next;
	}
	symtab = elf_create_section(SHT_SYMTAB, 0, 0);
	elf_name_section(symtab, ".symtab");
	set_hdr_info(symtab->header, sh_entsize, sym_size());
	set_hdr_info(symtab->header, sh_link, strtab->index);
	sym = (symbol *) malloc(sizeof(symbol));
	bzero(sym, sizeof(symbol));

	// For each version a new .text section must be created
	// create all the relocation sections we need form the knowledge
	// provided by the internal binary representation's versions registered
	for(ver = 0; ver < PROGRAM(versions); ver++) {
		switch_executable_version(ver);
		func = PROGRAM(code);

		// count the number of the registered functions and creates a
		// new section with the right dimension
		size = 0;
		while(func){
			size += func->symbol->size;
			func = func->next;
		}

		// Creates as much .text sections as the instrumentation versions
		text[ver] = elf_create_section(SHT_PROGBITS, size, SHF_EXECINSTR|SHF_ALLOC);

		bzero(secname, sizeof(secname));
		strcpy(secname, ".text");

		if(config.rules[ver]->suffix) {
			strcat(secname, ".");
			strcat(secname, (const char *)config.rules[ver]->suffix);
		}
		elf_name_section(text[ver], secname);

		// Relocation relative sections
		rela = elf_create_section(SHT_RELA, 0, 0);

		set_hdr_info(rela->header, sh_entsize, rela_size());
		set_hdr_info(rela->header, sh_link, symtab->index);
		set_hdr_info(rela->header, sh_info, text[ver]->index);

		rela->reference = 0;

		bzero(secname, sizeof(secname));
		strcpy((char *)secname, ".rela.text");

		if(config.rules[ver]->suffix) {
			strcat(secname, ".");
			strcat(secname, (const char *)config.rules[ver]->suffix);
		}
		elf_name_section(rela, secname);

		rela_text[ver] = rela;
	}

	// Creates the possible other relocation sections from the knowledge of
	// the original ELF file
	sec = PROGRAM(sections);
	while(sec) {
		// Looks for relocation section only that are relative to .text section
		// which is already taken into account previously

		if(sec->type == SECTION_RELOC) {
			// we now must decide to which section the new relocation section
			// will refers...
			rela->reference = sec;		//TODO: to payload!!
			target = sec_field(sec->index, sh_info);

			if(!strcmp(sec_name(target), ".text")) {
				sec = sec->next;
				continue;
			}

			// If we find a relocation section against rodata, we also take into account
			// the possibility that different versions have likely modified switch cases.
			// Therefore, in order to keep aligned the whole thing, we have to create
			// different versions of the rodata relocation as well.
			// Support to properly relocate against the new .rela.rodata.xyz is handled
			// by the function 'clone_text_relocation()' in handle-elf.c
		//	for(ver = 0; ver < PROGRAM(versions); ver++) {

				rela = elf_create_section(SHT_RELA, 0, 0);

				set_hdr_info(rela->header, sh_entsize, rela_size());
				set_hdr_info(rela->header, sh_link, symtab->index);

				if(!strcmp(sec_name(target), ".data")) {
					set_hdr_info(rela->header, sh_info, data->index);
					elf_name_section(rela, sec_name(sec->index));
					rela_data = rela;

				} else if(!strcmp(sec_name(target), ".rodata")) {
					set_hdr_info(rela->header, sh_info, rodata->index);

				/*	bzero(secname, sizeof(secname));
					strcpy((char *)secname, ".rela.rodata");
					if(config.rules[ver]->suffix) {
						strcat(secname, ".");
						strcat(secname, (const char *)config.rules[ver]->suffix);
					}
					elf_name_section(rela, secname);*/
					elf_name_section(rela, sec_name(sec->index));

					rela_rodata = rela;
				}

		//	}

		}
		sec = sec->next;
	}

	hnotice(3, "Allocating ELF header memory\n");

	// build the header info
	elf_build_eheader();

	hsuccess();
}



static void elf_update_symbol_list(symbol *first) {
	int idx = 0;
	int local = 0;		// it starts from 1 cause it takes into account the first null symbol
	symbol *sym, *prev;
	section *sec;

	// iterate all over the symbols to purge from the old file
	// and section symbols that do not hold anymore in the new generated code
	sym = first;
	while(sym) {
		// check if the symbol is already present in the section
		// and if the case, skip it
		if(sym->duplicate) {
			sym->index = idx - 1;
			sym = sym->next;
			continue;
		}

		// skip old section and file symbols
		// warning! relocation could be applied to these symbols
		// hence is mandatory to update the insn->reference field
		// accordingly, in such a case
		if(sym->type == SYMBOL_FILE) {
			sym->name = (unsigned char *)hijacked.path;
		} else if(sym->type == SYMBOL_SECTION) {
			hnotice(4, "Look for the section symbol name '%s' in the new section list...\n", sym->name);

			// check if the section will be present in the final code
			sec = hijacked.sections;
			sec = sec->next;
			while(sec) {
				// if the section's name is present in hijacked, then either the section does
				if(!strcmp(sym->name, (char *)sec->name)) {
					sym->secnum = sec->index;
					//sym->index = sec->index;
					sec = sec->next;

					hnotice(4, "Updated the section symbol index to %d\n", sym->secnum);
					break;
				}

				sec = sec->next;
			}

			if(!sec) {
				// no section will be found with the same name
				// thus skip the ignored section

				// TODO: da abilitare un supporto dinamico
				/*if(1) {
					// se è stata richiesta la creazione di tutte le sezioni originali
					// allora viene creata una nuova sezione a partire dal file originale

					sec = PROGRAM(sections);
					while(sec) {
						if(!strcmp(sym->name, (char *)sec->name)) {

							elf_create_section(sec->type, sec->size, sec->flags);
							sym->secnum = sec->index;
							//sym->index = sec->index;
							sec = sec->next;

							hnotice(4, "Updated the section symbol index to %d\n", sym->secnum);
							break;
						}

						sec = sec->next;
					}
				}*/

				hnotice(4, "Section will be ignored\n");

				sym->version = -1;

				prev->next = sym->next;
				sym = prev->next;
				continue;
			}
		}

		if(sym->bind == STB_LOCAL) {
			local++;
		}

		sym->index = idx++;

		hnotice(3, "[%d] Symbol '%s' of type %d (%s)\n", sym->index, sym->name, sym->type,
				sym->bind == STB_LOCAL ? "local" : sym->bind == STB_GLOBAL ? "global" : "weak");

		prev = sym;
		sym = sym->next;
	}

	// update the section info field the reports the total number of the local symbol registered
	set_hdr_info(symtab->header, sh_info, local);

	hnotice(3, "%d total symbols registered (%d are local)\n", idx, local);
}


static void elf_fill_sections(void) {
	symbol *sym;
	function *func;
	section *sec;
	long offset;
	unsigned int ver;
	void *content;
	long size;

	sym = PROGRAM(symbols);

	// update symbol references and indexes
	elf_update_symbol_list(sym);

	// ==== 1 ====
	// Fill text and reloc sections with the code in stored
	// in the function list with the relative relocation entries
	hnotice(2, "Fill text and relocations...\n");

	for (ver = 0; ver < PROGRAM(versions); ver++) {
		hnotice(3, "Writing code of version %d\n", ver);

		// For each version writes the code of each functions
		switch_executable_version(ver);
		func = PROGRAM(code);

		while(func) {
			hnotice(3, "Reading function '%s' (%d bytes)\n", func->name, func->symbol->size);
			hnotice(4, "Attempt to write on section '%s' (version %d)\n", text[func->symbol->version]->name, func->symbol->version);

			offset = elf_write_code(text[func->symbol->version], func);

			// update the symbol position reference in the .text
			// in order to correctly been processed in filling
			// symbol and data tables
			func->symbol->position = offset;

			func = func->next;
		}
	}

	// ==== 2 ====
	// Fill symtab section, strtab names and data sections with the
	// information provided with the registered symbols
	hnotice(2, "Fill symtab, stratb and data...\n");
	while(sym) {

		// skip symbol duplicates that are used only to handle
		// relocation offsets
		if(sym->duplicate) {
			sym = sym->next;
			continue;
		}

		sym->index = elf_write_symbol(symtab, sym, strtab, data);

		sym = sym->next;
	}

	// Fill rodata/bss sections
	hnotice(2, "Fill rodata/bss data sections...\n");
	sec = PROGRAM(sections);
	offset = 0;
	while(sec) {
		if(!strncmp(sec_name(sec->index), ".rodata", 7)) {
			sym = find_symbol((unsigned char *)sec_name(sec->index));
			//sym = find_symbol((unsigned char *)".rodata");
			if(sym == NULL){
				hinternal();
			}

			size = sec_size(sec->index);
			hnotice(3, "Copying raw data of section '%s' [%d] (%d bytes)\n", sym->name, sym->secnum, size);
			content = malloc(size);
			if(content == NULL) {
				herror(true, "Out of memory!\n");
			}

			// This is to handle the case that hijacker will adds indirectly data to pre-existent sections
			// i.e. in case of swith cases for different versions
			bzero(content, size);
			memcpy(content, sec->payload, size);
			elf_write_data(rodata, content, size);

		} else if(!strcmp(sec_name(sec->index), ".bss")) {
			sym = find_symbol((unsigned char *)sec_name(sec->index));
			if(sym == NULL){
				hinternal();
			}

			hnotice(3, "Copying raw data of section '%s' [%d] (%d bytes)\n", sym->name, sym->secnum, sym->size);
			elf_write_data(bss, sec->payload, sym->size);
		}

		sec = sec->next;
	}

	hnotice(2, "Writing remaining relocation entries...\n");
	// Here we write the remainder of the relocation, therefore
	// we must used versioned symbols instead of the whole list
	sym = PROGRAM(symbols);
	while(sym) {
		// For all the symbols still to be relocated...
		if(!sym->referenced) {
			sym = sym->next;
			continue;
		}

		if(!strncmp((const char *)sym->relocation.secname, ".text", 5)) {
			sec = rela_text[sym->version];
		} else if(!strcmp((const char *)sym->relocation.secname, ".rodata")) {
			sec = rela_rodata;
		} else if(!strcmp((const char *)sym->relocation.secname, ".data")) {
			sec = rela_data;
		} else {
			herror(false, "Relocation entry towards symobl '%s' has specified a non valid section name (%s): ignored\n",
				sym->name, sym->relocation.secname);
			sym = sym->next;
			continue;
		}

		if(sym->relocation.ref_insn) {
			//printf("Il simbolo %s (%d) punta all'istruzione <%#08llx>\n", sym->name, sym->version, sym->relocation.ref_insn->new_addr);
			sym->relocation.addend = sym->relocation.ref_insn->new_addr;
		}

		hnotice(3, "Relocation of type %d to symbol '%s'[%d] +%0lx (offset %0llx) in section '%s', has to be applied\n",
			sym->relocation.type, sym->name, sym->index, sym->relocation.addend, sym->relocation.offset, sym->relocation.secname);

		elf_write_reloc(sec, sym, sym->relocation.offset, sym->relocation.addend);

		sym = sym->next;
	}
}


/**
 * Generates the new object file.
 */
void elf_generate_file(char *path) {
	FILE *file = NULL;
	section *sec;
	int shnum;
	long offset;

	hnotice(1, "Initializing a new ELF file...\n");
	elf_build();

	// Open the output file and write the content
	hnotice(1, "Creating a new output file...\n");

	// if not a valid path is provided, the standard one is used
	if(!path) {
		path = malloc(sizeof(char *));
		strcpy(path, DEFAULT_OUT_NAME);
	}

	file = fopen(path, "w+");
	if (!file) {
		herror("Unable to write output ELF file '%s'!\n", path);
	}

	hijacked.path = malloc(strlen(path) + 1);
	strcpy(hijacked.path, path);

	// reserver the initial space for the elf header that will be written
	// in the final pass
	fseek(file, ehdr_size(), SEEK_SET);

	// Now pass to filling virtual section descriptors with
	// the content the final output ELF file should have
	elf_fill_sections();

	// Starting to write section after the ELF's header
	// Writes all registered sections
	hnotice(2, "Copying sections content...\n");
	sec = hijacked.sections;
	shnum = 0;
	while(sec) {
		// now we shrink the size of the section in order to envelop exactly section's content
		// and subsequently, the section will be copied into the file. this is done for all sections registered
		shrink_section_size(sec);
		set_hdr_info(sec->header, sh_addralign, 1);

		if(sec->type == SECTION_SYMBOLS) {
			set_hdr_info(sec->header, sh_addralign, 8);
		}

		offset = elf_write_section(file, sec);
		set_hdr_info(sec->header, sh_offset, offset);
		shnum++;

		sec = sec->next;
	}

	// at this point all sections are copied into the ELF file
	// and it is possible to update the information in the ELF's header
	// of how much sections are presents
	// further the current file pointer represents the starting offset from
	// which sections' headers begin.
	offset = ftell(file);
	set_elfhdr_info(hijacked.ehdr, e_shnum, shnum);
	set_elfhdr_info(hijacked.ehdr, e_shoff, offset);

	// Write sections' headers
	hnotice(2, "Copying sections' headers...\n");
	hnotice(3, "Section headers starting from offset <%#08lx>\n", offset);
	sec = hijacked.sections;
	while(sec) {
		offset = elf_write_section_header(file, sec);
		sec = sec->next;
	}

	// go to the starting byte of file and write the elf header
	hnotice(2, "Copying the ELF's header...\n");

	rewind(file);
	fwrite(hijacked.ehdr, ehdr_size(), 1, file);
	fclose(file);
}
