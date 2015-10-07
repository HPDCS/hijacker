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
* @file executable.h
* @brief Structures to handle executable formats
* @author Alessandro Pellegrini
* @author Davide Cingolani
* @author Simone Economo
*/

#pragma once
#ifndef _EXECUTABLE_H
#define _EXECUTABLE_H

#include <ibr.h>
#include <elf/elf-defs.h>


#define EXECUTABLE_ELF	1

#define MAX_VERSIONS	256

typedef struct _executable {
	int type;
	int insn_set;
	union {
		elf_file	elf;
	} e;
	symbol		*orig_syms;
	function	*v_code[MAX_VERSIONS];
	unsigned int	version;	/// Current instrumenting version
	unsigned int	versions;	/// Number of total versions
	void 		*metadata;
	unsigned int	symnum;
	symbol		*symbols;
	unsigned int	secnum;
	section		*sections;
	function	*code;		// [DC] Added this field to handle the parsed functions
	void 	*rawdata;		// [DC] Added this filed to handle preallocated raw data
	block *blocks[MAX_VERSIONS];		// [SE] Basic block overlay
} executable_info;



extern void load_program(char *path);
extern void output_object_file(char *pathname);

#endif /* _EXECUTABLE_H */

