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
* @file elf-defs.h
* @brief ELF-related abstraction definitions
* @author Alessandro Pellegrini
* @date September 22, 2008
*/

#ifndef _ELF_DEFS_H
#define _ELF_DEFS_H

#include <stdio.h>
#include <elf.h>

#include <stdbool.h>

#define NO_REL	0
#define IS_REL	1
#define IS_RELA 2


typedef union {
	Elf32_Ehdr header32;
	Elf64_Ehdr header64;
} Elf_Hdr;


typedef union {
	Elf32_Off offset32;
	Elf64_Off offset64;
} Elf_Off;


typedef union {
	Elf32_Shdr section32;
	Elf64_Shdr section64;
} Section_Hdr;


typedef union {
	Elf32_Rel rel32;
	Elf64_Rel rel64;
} Elf_Rel;


typedef union {
	Elf32_Rela rel32;
	Elf64_Rela rel64;
} Elf_Rela;


typedef union {
	Elf64_Sym sym64;
	Elf32_Sym sym32;
} Elf_Sym;


typedef struct {
	FILE *pointer;			// Il file descriptor
	bool is64;			// 32 o 64 bit?
	unsigned char *data;		// elf file loaded in memory

	Elf_Hdr	*hdr;
	Section_Hdr *sec_hdr;
	unsigned int secnum;
} elf_file;


/// Macro to quickly access ELF-Related data structure
#define ELF(field) (config.program.e.elf.field)

/// Macro to get ELF section size by its index
#define sec_size(sec)   ((int)( ELF(is64) ? ELF(sec_hdr)[(sec)].section64.sh_size : ELF(sec_hdr)[(sec)].section32.sh_size ))

/// Macro to get ELF section header address
#define sec_header(sec) (&ELF(sec_hdr)[sec])

/// Macro to get ELF section content
#define sec_content(sec)\
	     (ELF(is64)\
		? (ELF(data) + sec_header(sec)->section64.sh_offset)\
		: (ELF(data) + sec_header(sec)->section32.sh_offset)\
             )

/// [DC] Macro to get ELF section content
#define sec_field(sec, field)\
	     (ELF(is64)\
		? (sec_header(sec)->section64.field)\
		: (sec_header(sec)->section32.field)\
             )

/// Macro for getting section header string table's index
#define shstrtab_idx() \
		(ELF(is64)\
		  ? (ELF(hdr)->header64.e_shstrndx) \
		  : (ELF(hdr)->header32.e_shstrndx) \
	     	)

/// Macro for accessing section header string table
#define shstrtab(pos) (char *)(sec_content(shstrtab_idx()) + (pos))

/// Macro to get ELF section name by its index
#define sec_name(sec)\
             (ELF(is64)\
        	? ( shstrtab(sec_header(sec)->section64.sh_name) ) \
        	: ( shstrtab(sec_header(sec)->section32.sh_name) ) \
	     )

/// Macro to get ELF section type
#define sec_type(sec)\
	     (ELF(is64)\
		? ( sec_header(sec)->section64.sh_type ) \
		: ( sec_header(sec)->section32.sh_type ) \
	     )


/// Macro to get ELF section flags
#define sec_flags(sec)\
	     (ELF(is64)\
		? ( sec_header(sec)->section64.sh_flags ) \
		: ( sec_header(sec)->section32.sh_flags ) \
	     )

/// Macro to test ELF section flags
/*#define sec_test_flag(sec, flag)\
	     (ELF(is64)\
		? ( (sec_header(sec)->section64.sh_flags && (flag)) != 0) \
		: ( (sec_header(sec)->section32.sh_flags && (flag)) != 0) \
	     )*/

/// Macro to test ELF section flags
#define sec_test_flag(sec, flag)\
	     (ELF(is64)\
		? ( (sec_header(sec)->section64.sh_flags & (flag)) != 0) \
		: ( (sec_header(sec)->section32.sh_flags & (flag)) != 0) \
	     )

/// Macro for accessing Symbol Tables' Entries
#define symbol_info(s, f)	(ELF(is64)\
					? (s)->sym64.f\
					: (s)->sym32.f\
				)

/// Macro to access a relocation field (either REL or RELA)
#define reloc_info(r, f)	(ELF(is64)	\
					? (r)->rel64.f		\
					: (r)->rel32.f		\
				)

extern void elf_create_map(void);
extern int elf_instruction_set(void);
extern bool is_elf(char *path);

#endif /* _ELF_DEFS_H */

