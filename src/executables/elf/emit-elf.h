/*
 * emit-elf.h
 *
 *  Created on: 20/mag/2014
 *      Author: davide
 */

#ifndef EMIT_ELF_H_
#define EMIT_ELF_H_

#include "elf-defs.h"
#include "executable.h"

typedef struct _hijacked_elf {
	Elf_Hdr *ehdr;			/// ELF's header descriptor
	section *sections;		/// Section list contained by the hijacked ELF file
	char *path;				/// Path of the hijacked ELF file
} hijacked_elf;

/// Macro to get the current elf header size relative to machine type
#define ehdr_size() ELF(is64) ? sizeof(Elf64_Ehdr) : sizeof(Elf32_Ehdr)

/// Macro to get the current section header size relative to machine type
#define shdr_size() ELF(is64) ? sizeof(Elf64_Shdr) : sizeof(Elf32_Shdr)

/// Macro to get the current symbol size relative to machine type
#define sym_size() ELF(is64) ? sizeof(Elf64_Sym) : sizeof(Elf32_Sym)

/// Macro to get the current symbol size relative to machine type
#define rela_size() ELF(is64) ? sizeof(Elf64_Rela) : sizeof(Elf32_Rela)


/// Macro to access ELF section field
#define ehdr_info(hdr, field)\
	(ELF(is64)\
	? ((hdr)->header64.field)\
	: ((hdr)->header32.field)\
	  )

/// Macro to access section header field
#define header_info(hdr, field)\
	 (ELF(is64)\
	? ((hdr)->section64.field)\
	: ((hdr)->section32.field)\
		 )

#define set_hdr_info(hdr, field, value)\
		if(ELF(is64)){\
			(((Section_Hdr*)(hdr))->section64.field) = value;\
		} else {\
			(((Section_Hdr*)(hdr))->section32.field) = value;\
		}

#define set_elfhdr_info(hdr, field, value)\
		if(ELF(is64)){\
			(((Elf_Hdr*)(hdr))->header64.field) = value;\
		} else {\
			(((Elf_Hdr*)(hdr))->header32.field) = value;\
		}

#define set_sym_info(sym, filed, value)\
		if(ELF(is64)){\
			(((symbol*)(sym))->sym64.field) = value;\
		} else {\
			(((symbol*)(sym))->sym32.field) = value;\
		}


/**
 * Generates the new object file.
 */
void elf_generate_file(char *path, int flags);


#endif /* EMIT_ELF_H_ */
