#if 0

#include <err.h>
#include <fcntl.h>
#include <libelf.h>
#include <stdio.h>
#include <stdlib.h>
#include <sysexits.h>
#include <unistd.h>

#define LOADADDR    0x08048000

unsigned char code[] = {
		0xBB, 0x2A, 0x00, 0x00, 0x00, /* movl $42, %ebx */
		0xB8, 0x01, 0x00, 0x00, 0x00, /* movl $1, %eax */
		0xCD, 0x80 /* int $0x80 */
};

unsigned char strtab_ptr[] = {
		0, '.', 't', 'e', 'x', 't', 0,
		'.', 's', 'h', 's', 't', 'r', 't', 'a', 'b', 0
};

int main(int argc, char *argv[]) {
	int fd;
	Elf *e;
	Elf_Scn *scn;
	Elf_Data *data;
	Elf64_Ehdr *ehdr;
	Elf64_Phdr *phdr;
	Elf64_Shdr *shdr;
	if (argc != 2)
		errx(EX_USAGE, "input... ./%s filename\n", argv[0]);
	if (elf_version(EV_CURRENT) == EV_NONE)
		errx(EX_SOFTWARE, "elf_version is ev_none, wtf? %s\n",
				elf_errmsg(-1));
	if ((fd = open(argv[1], O_WRONLY | O_CREAT, 0777)) < 0)
		errx(EX_OSERR, "open %s\n", elf_errmsg(-1));
	if ((e = elf_begin(fd, ELF_C_WRITE, NULL)) == NULL)
		errx(EX_SOFTWARE, "elf_begin %s\n", elf_errmsg(-1));
	if ((ehdr = elf64_newehdr(e)) == NULL)
		errx(EX_SOFTWARE, "elf64_newehdr %s\n", elf_errmsg(-1));
	/*
	 without these definitions objdump/readelf/strace/elf loader
	 will fail to load the binary correctly
	 be sure to pick them carefully and correctly, preferred exactly like the
	 ones like the system you are running on (so if you are running x86,
	 pick the same values you seen on a regular readelf -a /bin/ls
	 */
	size_t ehdrsz, phdrsz;

	ehdrsz = elf64_fsize(ELF_T_EHDR, 1, EV_CURRENT);
	phdrsz = elf64_fsize(ELF_T_PHDR, 1, EV_CURRENT);

	ehdr->e_ident[EI_DATA] = ELFDATA2LSB;
	ehdr->e_ident[EI_CLASS] = ELFCLASS64;
	ehdr->e_machine = EM_386;
	ehdr->e_type = ET_EXEC;
	ehdr->e_entry = LOADADDR + ehdrsz + phdrsz;

	if ((phdr = elf64_newphdr(e, 1)) == NULL)
		errx(EX_SOFTWARE, "elf64_newphdr %s\n", elf_errmsg(-1));
	if ((scn = elf_newscn(e)) == NULL)
		errx(EX_SOFTWARE, "elf64_newscn %s\n", elf_errmsg(-1));

	if ((data = elf_newdata(scn)) == NULL)
		errx(EX_SOFTWARE, "elf64_newdata %s\n", elf_errmsg(-1));

	data->d_align = 1;
	data->d_off = 0LL;
	data->d_buf = code;
	data->d_type = ELF_T_BYTE;
	data->d_size = sizeof(code);
	data->d_version = EV_CURRENT;
	if ((shdr = elf64_getshdr(scn)) == NULL)
		errx(EX_SOFTWARE,"elf64_getshdr %s\n", elf_errmsg(-1));

	shdr->sh_name = 1; /* Offset of ".text", see below. */
	shdr->sh_type = SHT_PROGBITS;
	shdr->sh_flags = SHF_EXECINSTR | SHF_ALLOC;
	shdr->sh_addr = LOADADDR + ehdrsz + phdrsz;
	if ((phdr = elf64_newphdr(e,1)) == NULL)
		errx(EX_SOFTWARE,"elf64_newphdr %s\n", elf_errmsg(-1));

	phdr->p_type = PT_LOAD;
	phdr->p_offset = 0;
	phdr->p_filesz = ehdrsz + phdrsz + sizeof(code);
	phdr->p_memsz = phdr->p_filesz;
	phdr->p_vaddr = LOADADDR;
	phdr->p_paddr = phdr->p_vaddr;
	phdr->p_align = 4;
	phdr->p_flags = PF_X | PF_R;
	elf_flagphdr(e, ELF_C_SET, ELF_F_DIRTY);
	if (elf_update(e, ELF_C_WRITE) < 0)
		errx(EX_SOFTWARE, "elf64_update_2 %s\n", elf_errmsg(-1));

	elf_end(e);
	close(fd);
	return 1;
}

#endif /* 0 */
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <hijacker.h>
#include <prints.h>
#include <executable.h>

#include "elf-defs.h"
#include "handle-elf.h"
#include "emit-elf.h"

#define SECTION_INIT_SIZE 1024

hijacked_elf hijacked;		/// Hijacked output ELF descriptor

/**
 * Commodity pointers to default section's payloads
 */
static section *shstrtab;
static section *strtab;
static section *symtab;
static section *rodata;
static section *text;
static section *rela_text;
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
	unsigned long long size;


	hdr = (Section_Hdr *) sec->header;

	offset = (sec->ptr - sec->payload);
	size = header_info(hdr, sh_size);

	hnotice(6, "Check if section %u has enough available space....: Available = %u, Needed = %u\n", sec->index,
			(size - offset), span);
	hnotice(6, "Offset= %ld, size= %ld\n", offset, size);

	if(!size)
		size = SECTION_INIT_SIZE;

	if(!sec->ptr) {
		sec->ptr = sec->payload = malloc(size);
		hnotice(6, "Allocated %d bytes for section %d\n", size, sec->index);
		
	} else if ((sec->ptr + span) >= (sec->payload + size)) {
		sec->ptr = sec->payload = realloc(sec->payload, size *= 2);
		sec->ptr += offset;		// Replace 'ptr' to the original displacement in the newly allocated block
		hnotice(6, "Doubling size of section %u to %u...\n", sec->index, size);
	}

	// update the size into the section header
	set_hdr_info(hdr, sh_size, size);
}


/**
 * Given a section it shrinks its size to the exact one
 *
 * @param sec Section descriptor
 *
 * @return Returns the final size in bytes
 */
inline static long shrink_section_size(section *sec) {
	long size;
	Section_Hdr *hdr;

	hdr = sec->header;
	size = (sec->ptr - sec->payload);

	if(size < 0)
		hinternal();

	sec->payload = realloc(sec->payload, size);

	set_hdr_info(hdr, sh_size, size);

	hnotice(3, "Section %d size shrink to %u bytes\n", sec->index, size);

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

	if(!buffer)
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
	sec->ptr += buflen;

	hnotice(4, "String written to .strtab section at offset <%#08lx> :: '%s'\n",
			(ptr - sec->payload), buffer);

	return (ptr - sec->payload);
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
	sec->ptr += size;

	hnotice(3, "Read only data written into .rodata section at offset <%#08lx>\n", (ptr - sec->payload));

	return (ptr - sec->payload);
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
	sec->ptr += size;

	hnotice(3, "Written symbol value into section %u at offset <%#08lx>\n", sec->index, (ptr - sec->payload));
	hdump(4, "Data buffer dump", buffer, size);

	return (ptr - sec->payload);
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
int elf_write_symbol(section *symtab, symbol *sym, section *strtab, section *data) {
	Elf_Sym *entry;
	Elf64_Sym *sym64;
	Elf32_Sym *sym32;
	Section_Hdr *hdr;
	function *func;
	int size;
	int shndx = 0;
	void *ptr;

	// build a new symbol entry accordingly to the ELF class
	size = sym_size();
	entry = (Elf_Sym *) malloc(size);
	shndx = sym->secnum;		// TODO: here?
	bzero(entry, size);

	hdr = (Section_Hdr *) symtab->header;

	if(ELF(is64)) {
		sym64 = &(entry->sym64);

		switch(sym->type) {
		case SYMBOL_FUNCTION:
			// its starting offset it is already been evaluated in a previous pass
			shndx = text->index;	// TODO: it must be updated in order to support multiple .text sections
			break;

		case SYMBOL_VARIABLE:
			// verify if the object has to be binded to the COMMON section,
			// that is the variable is not allocated yet; otherwise .data section
			// must be filled up with the relative content
			if(sym->secnum != SHN_COMMON) {
				sym->position = elf_write_data(data, &sym->position, sym->size);
				shndx = data->index;	// TODO: it must be updated in order to support multiple .data sections
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

		// write the symbol name into the strtab and get the offset to store in st_name
		sym64->st_name = elf_write_string(strtab, sym->name);
		sym64->st_value = sym->position;
		sym64->st_size = sym->size;
		sym64->st_info = ELF64_ST_INFO(sym->bind, sym->type);
		sym64->st_shndx = shndx;

	} else {
		sym32 = &(entry->sym32);

		switch(sym->type) {
		case SYMBOL_FUNCTION:
			// its starting offset it is already been evaluated in a previous pass
			shndx = text->index;	// TODO: it must be updated in order to support multiple .text sections
			break;

		case SYMBOL_VARIABLE:
			// verify if the object has to be binded to the COMMON section,
			// that is the variable is not allocated yet; otherwise .data section
			// must be filled up with the relative content
			if(sym->secnum != SHN_COMMON) {
				sym->position = elf_write_data(data, &sym->position, sym->size);
				shndx = data->index;	// TODO: it must be updated in order to support multiple .data sections
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

		// write the symbol name into the strtab and get the offset to store in st_name
		sym32->st_name = elf_write_string(strtab, sym->name);
		sym32->st_value = sym->position;
		sym32->st_size = sym->size;
		sym32->st_info = ELF32_ST_INFO(sym->bind, sym->type);
		sym32->st_shndx = shndx;
	}

	// check if section must be enlarged
	check_section_size(symtab, size);

	// copy the information handled by symbol hjacker's descriptor into the elf's entry
	memcpy(symtab->ptr, entry, size);
	ptr = symtab->ptr;
	symtab->ptr += size;

	hnotice(3, "Symbol [%u] '%s' (type %d and bind %d) written into section %u at offset <%#08lx>\n", sym->index, sym->name,
			sym->type, sym->bind, symtab->index, (ptr - symtab->payload));

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
	insn_info *insn;
	int machine;
	unsigned long offset;
	unsigned long written;
	unsigned long long total_size = 0;

	insn = func->insn;
	while(insn != NULL) {
		total_size += insn->size;
		insn = insn->next;
	}

	// otherwise relocations entries are doubled
	sec->reference = 0;

	check_section_size(sec, total_size);

	// save the current content pointer in order to have the
	// starting offset from which the function begins
	offset = (unsigned long) (sec->ptr - sec->payload);
	written = 0;

	machine = ELF(is64) ? ELF(hdr)->header64.e_machine : ELF(hdr)->header32.e_machine;

	hnotice(3, "Writing function's data to text section...\n");

	switch (machine) {
	case -1:
		herror(true, "Instruction code not yet implemented...\n");
		break;

	case EM_X86_64:
		written += write_x86_code(func, sec, rela_text);
		break;

	default:
		herror(true, "Architecture type not recognized!\n");
	}

	hnotice(3, "Function '%s' copied (%u bytes)\n", func->name, written);

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
	int type;

	//hnotice(3, "Creating rela entry...\n");

	// mhh, should not happen here, but...
	if(!sec) {
		herror(false, "A relocation entry was not added: target section seems does not exist!\n");
		return -1;		// TODO: is it correct to return -1 in case of error?
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
	sec->ptr += sizeof(Elf_Rela);

	// Marks the symbol as unreferenced, since it is resolved;
	// in this way we prevent that subsequent parsing will
	// create same entries
	sym->referenced = 0;

	hnotice(3, "Written relocation entry at offset <%#08lx> to symbol '%s' %+d\n", addr, sym->name, addend);


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
	int index;

	shsize = shdr_size();
	hdr = (Section_Hdr *) malloc(shsize);
	bzero(hdr, shsize);

	sec = (section *) malloc(sizeof(section));
	bzero(sec, sizeof(section));

	sec->header = hdr;

	if(ELF(is64)) {
		hdr64 = &(hdr->section64);

		// Increment the number of all sections if a new one is created
		index = hijacked.ehdr->header64.e_shnum++;

		//	hdr64->sh_name = elf_write_string(shstrtab, name);
		hdr64->sh_type = type;
		hdr64->sh_flags = flags;

		// if section's size is provide set it to its header
		// otherwise the implicit automatic resizing mechanism is used
		hdr64->sh_size = size;

	} else {
		hdr32 = &(hdr->section32);

		// Increment the number of all sections if a new one is created
		index = hijacked.ehdr->header32.e_shnum++;

		//	hdr32->sh_name = elf_write_string(shstrtab, name);
		hdr32->sh_type = type;
		hdr32->sh_flags = flags;

		// if section's size is provide set it to its header
		// otherwise the implicit automatic resizing mechanism is used
		hdr32->sh_size = size;
	}

	hnotice(3, "Section of type %d of %d bytes created with index %d\n", type, size, index);

	sec->index = index;
	sec->type = type;


	// links created sections together
	if(!hijacked.sections)
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

	sec->name = name;

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

	hnotice(3, "Section copied (%u bytes) starting from <%#08lx>\n", header_info(hdr, sh_size), offset);
	hsuccess();

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
	Section_Hdr *hdr;
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
static void elf_build_eheader() {
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


static elf_build() {
	long size;
	symbol *sym, *prev;
	function *func;

	sym = PROGRAM(symbols);
	func = PROGRAM(code);

	// build the descriptor for the output elf
	hijacked.ehdr = malloc(ehdr_size());

	// the very first section must be the null one
	elf_create_section(SHT_NULL, 0, 0);

	// then it is needed the sections' name string table
	shstrtab = elf_create_section(SHT_STRTAB, 0, 0);
	elf_write_string(shstrtab, "");
	elf_name_section(shstrtab, ".shstrtab");


	// start to build each standard section
	hnotice(3, "Allocating sections memory\n");

	strtab = elf_create_section(SHT_STRTAB, 0, 0);
	elf_name_section(strtab, ".strtab");
	elf_write_string(strtab, "");

	// count the number of the registered functions and creates a
	// new section with the right dimension
	size = 0;
	while(func){
		size += func->symbol->size;
		func = func->next;
	}
	text = elf_create_section(SHT_PROGBITS, size, SHF_EXECINSTR|SHF_ALLOC);
	elf_name_section(text, ".text");

	data = elf_create_section(SHT_PROGBITS, 0, SHF_ALLOC|SHF_WRITE);
	elf_name_section(data, ".data");

	bss = elf_create_section(SHT_NOBITS, 0, SHF_ALLOC|SHF_WRITE);
	elf_name_section(bss, ".bss");

	rodata = elf_create_section(SHT_PROGBITS, 0, SHF_ALLOC);
	elf_name_section(rodata, ".rodata");

	// count the number of the registered symbols and creates a
	// new section with the right dimension
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


	// create all the relocation sections we need form the knowledge
	// provided by the parsing of the original ELF file
	section *sec = PROGRAM(sections);
	section *rela;
	int target;
	while(sec) {
		if(sec->type == SECTION_RELOC) {
			rela = elf_create_section(SHT_RELA, 0, 0);
			elf_name_section(rela, sec_name(sec->index));

			set_hdr_info(rela->header, sh_entsize, rela_size());
			set_hdr_info(rela->header, sh_link, symtab->index);

			// we now must decide to which section the new relocation section
			// will refers...
			rela->reference = sec;		//TODO: to payload!!
			target = sec_field(sec->index, sh_info);

			if(!strcmp(sec_name(target), ".text")) {
				set_hdr_info(rela->header, sh_info, text->index);

				// it not needed to specify a relocation entry since references are already
				// retrieved by the specific instruction set code emitter
				rela->reference = 0;
				rela_text = rela;

			} else if(!strcmp(sec_name(target), ".data")) {
				set_hdr_info(rela->header, sh_info, data->index);
				rela_data = rela;

			} else if(!strcmp(sec_name(target), ".rodata")) {
				set_hdr_info(rela->header, sh_info, rodata->index);
				rela_rodata = rela;

			}

		}
		sec = sec->next;
	}

	// at least one rela section is needed, hence if no rela section was created
	// then create one in order to support monitor instrumentation
	if(!rela_text) {
		rela = elf_create_section(SHT_RELA, 0, 0);

		set_hdr_info(rela->header, sh_entsize, rela_size());
		set_hdr_info(rela->header, sh_link, symtab->index);
		set_hdr_info(rela->header, sh_info, text->index);

		rela->reference = 0;
		elf_name_section(rela, ".rela.text");

		rela_text = rela;
	}

	hnotice(3, "Allocating ELF header memory\n");

	// build the header info
	elf_build_eheader();

	hsuccess();
}



static void elf_update_symbol_list(symbol *first) {
	int index = 0;
	int local = 0;		// it starts from 1 cause it takes into account the first null symbol
	symbol *sym, *prev, *node;
	section *sec;

	// iterate all over the symbols to purge from the old file
	// and section symbols that do not hold anymore in the new generated code
	sym = first;
	while(sym) {
		// check if the symbol is already present in the section
		// and if the case, skip it
		if(sym->duplicate) {
			sym->index = index - 1;
			sym = sym->next;
			continue;
		}

		// skip old section and file symbols
		// warning! relocation could be applied to these symbols
		// hence is mandatory to update the insn->reference field
		// accordingly in such a case
		if(sym->type == SYMBOL_FILE) {// || sym->type == SYMBOL_SECTION) {
			sym->name = hijacked.path;
		} else if(sym->type == SYMBOL_SECTION) {
			hnotice(5, "Look for the section symbol name '%s' in the new section list...\n", sym->name);

			// check if the section will be present in the final code
			sec = hijacked.sections;
			sec = sec->next;
			while(sec) {
				// if the section's name is present in hijacked, then either the section does
				if(!strcmp(sec_name(sym->secnum), sec->name)) {
					sym->secnum = sec->index;
					//sym->index = sec->index;
					sec = sec->next;

					hnotice(5, "Updated the section symbol index to %d\n", sym->secnum);
					break;
				}

				sec = sec->next;
			}

			if(!sec) {
				// no section will be found with the same name
				// thus skip the ignored section
				hnotice(5, "Skip section symbol since it will be ignored\n");

				prev->next = sym->next;
				sym = prev->next;
				continue;
			}
		}

		if(sym->bind == STB_LOCAL) {
			local++;
		}

		sym->index = index++;

		hnotice(3, "[%d] Symbol '%s' of type %d (%s)\n", sym->index, sym->name, sym->type,
				sym->bind == STB_LOCAL ? "local" : sym->bind == STB_GLOBAL ? "global" : "weak");

		prev = sym;
		sym = sym->next;
	}

	// update the section info field the reports the total number of the local symbol registered
	set_hdr_info(symtab->header, sh_info, local);

	hnotice(4, "%d total symbols registered (%d are local)\n", index, local);
}




/**
 * Remove old unused section's symbols and update indexes accordingly.
 * Besides updating all the symbol with respect to the new ELF file that
 * must be generated, it counts the number of all LOCAL symbols presents
 * in the section. This parameter is essential in order to allow LD to
 * link correctly the object file, otherwise errors could occur.
 *
 * @param first Symbol descriptor of the first symbol in the list
 */
/*static void elf_update_symbol_list(symbol *first) {
	int index = 0;
	int local = 1;		// it starts from 1 cause it takes into account the first null symbol
	symbol *sym, *prev, *node;
	section *sec;

	// iterate all over the symbols to purge from the old file
	// and section symbols that do not hold anymore in the new generated code
	sym = first;
	while(sym) {
		// skip old section and file symbols
		// warning! relocation could be applied to these symbols
		// hence is mandatory to update the insn->reference field
		// accordingly in such a case
		if(sym->type == SYMBOL_FILE) {// || sym->type == SYMBOL_SECTION) {
			//prev->next = sym->next;
			sym->name = hijacked.path;
			sym->index = index;
			//sym = prev->next;
			//continue;
		} else if(sym->type == SYMBOL_SECTION) {
			// check if this symbol has been referenced at least one time
			if(sym->referenced)
		}

		prev = sym;
		sym = sym->next;
	}


	// TODO:  since now there is the new function to create a new symbol node, use it!
	// builds the new filename symbol
	sym = (symbol *) malloc(sizeof(symbol));
	bzero(sym, sizeof(symbol));
	sym->secnum = SHN_ABS;
	sym->type = SYMBOL_FILE;
	sym->bind = STB_LOCAL;
	sym->extra_flags = (ELF(is64) ? ELF64_ST_BIND(STB_LOCAL) : ELF32_ST_BIND(STB_LOCAL));
	sym->name = hijacked.path;	//TODO: to adjust to only name
	sym->index = index++;

	sym->next = first->next;
	first->next = sym;
	local++;		// filename symbol is LOCAL, thus increment the counter


	// all the file and sections symbols are remove, now
	// we have to add the new ones
	// populate new sections' symbols
	sec = hijacked.sections;
	prev = sym;
	while(sec) {
		// check if this section has to have an associated symbol to it
		if(sec->type != SHT_PROGBITS && sec->type != SHT_NOBITS) {
			sec = sec->next;
			continue;
		}

		sym = (symbol *) malloc(sizeof(symbol));
		bzero(sym, sizeof(symbol));
		sym->secnum = sec->index;
		sym->name = sec_name(sec->index);
		sym->type = SYMBOL_SECTION;
		sym->bind = STB_LOCAL;
		sym->index = index++;
		local++;			// section symbols are always LOCAL, hence we must increment the counter

		sym->next = prev->next;
		prev->next = sym;
		prev = sym;

		hnotice(3, "Section %d (%s) bind to symbol %d\n", sec->index, sym->name, sym->index);

		sec = sec->next;
	}

	// update existing symbols
	sym = prev->next;
	while(sym) {

		// check if the symbol is already present in the section
		// and if the case, skip it
		if(sym->duplicate) {
			sym->index = index - 1;

			hnotice(4, "Duplicate of symbol %d (%s) found; skipped!\n", sym->index, sym->name);

			sym = sym->next;
			continue;
		}

		sym->index = index++;

		// increment if the symbol is local (needed for sh_info field)!
		if (sym->bind == STB_LOCAL) {
			local++;
		}

		hnotice(3, "Update symbol '%s' to index %d\n", sym->name, sym->index);

		prev = sym;
		sym = sym->next;
	}


	// print out all the registerd symbols (no duplicates)
	sym = first;
	while(sym) {
		if(!sym->duplicate) {
			hnotice(3, "[%d] Symbol '%s' of type %d (%s)\n", sym->index, sym->name, sym->type,
				sym->bind == STB_LOCAL ? "local" : sym->bind == STB_GLOBAL ? "global" : "weak");

			// TODO: debug
			hprint("%p\n", sym);
		}
		sym = sym->next;
	}

	// update the section info field the reports the total number of the local symbol registered
	set_hdr_info(symtab->header, sh_info, local);

	hnotice(4, "%d total symbols registered (%d are local)\n", index, local);
}*/

static void elf_fill_sections() {
	symbol *sym;
	function *func;
	section *sec;
	long offset;
	int sym_count;
	int target, flags;

	sym = PROGRAM(symbols);
	func = PROGRAM(code);

	// update symbol references and indexes
	elf_update_symbol_list(sym);

	// ==== 1 ====
	// Fill text and reloc sections with the code in stored
	// in the function list with the relative relocation entries
	hnotice(2, "Fill text and relocations...\n");

	while(func) {
		hnotice(3, "Reading function '%s'\n", func->name);

		offset = elf_write_code(text, func);

		// update the symbol position reference in the .text
		// in order to correctly been processed in filling
		// symbol and data tables
		func->symbol->position = offset;

		func = func->next;
	}
	hsuccess();

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
	while(sec) {
		if(!strcmp(sec_name(sec->index), ".rodata")) {
			hnotice(3, "Copying raw data of section %d (%d bytes)\n", sec->index, sec_size(sec->index));
			elf_write_data(rodata, sec->payload, sec_size(sec->index));

		} else if(!strcmp(sec_name(sec->index), ".bss")) {
			hnotice(3, "Copying raw data of section %d (%d bytes)\n", sec->index, sec_size(sec->index));
			elf_write_data(bss, sec->payload, sec_size(sec->index));

		}

		sec = sec->next;
	}
/*
	// write the other relocation entries
	sec = hijacked.sections;
	while(sec) {
		// check if the section has relocation references
		if(sec->reference) {

			reloc *rel;
			rel = (reloc *)((section *)(sec->reference))->payload;

			while(rel && rel->symbol) {
				elf_write_reloc(sec, rel->symbol, rel->offset, rel->addend);
				rel = rel->next;
			}
		}
		sec = sec->next;
	}*/

	sym = PROGRAM(symbols);
	while(sym) {
		// For all the symbols still to be relocated...
		if(!sym->referenced) {
			sym = sym->next;
			continue;
		}
		
		if(!strcmp(sym->relocation.secname, ".text")) {
			sec = rela_text;
		} else if(!strcmp(sym->relocation.secname, ".rodata")) {
			sec = rela_rodata;
		} else if(!strcmp(sym->relocation.secname, ".data")) {
			sec = rela_data;
		} else {
			herror(false, "The relocation entry has specified a non valid section name: ignored\n");
			sym = sym->next;
			continue;
		}
		
		hprint("Da applicare una rilocazione di tipo %d al simbolo '%s' +%0lx (offset %0x) nella sezione '%s'\n",
			sym->relocation.type, sym->name, sym->relocation.addend, sym->relocation.offset, sym->relocation.secname);
		
		elf_write_reloc(sec, sym, sym->relocation.offset, sym->relocation.addend);
		
		sym = sym->next;
	}

	hsuccess();
}


/**
 * Generates the new object file.
 */
void elf_generate_file(char *path, int flags) {
	FILE *file;
	section *sec;
	int ehsize;
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

	hijacked.path = malloc(strlen(path));
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

		if(sec->type == SECTION_SYMBOLS)
			set_hdr_info(sec->header, sh_addralign, 8);

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

	hsuccess();
	hprint("File ELF written in '%s'\n", path);
}
