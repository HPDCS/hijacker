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

#pragma once
#ifndef _EMIT_ELF_H
#define _EMIT_ELF_H

#include <executable.h>

#include <elf/elf-defs.h>

#define SECNAME_SIZE 256


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
void elf_generate_file(char *path);
long elf_write_reloc(section *sec, symbol *sym, unsigned long long addr, long addend);


#endif /* _EMIT_ELF_H */
