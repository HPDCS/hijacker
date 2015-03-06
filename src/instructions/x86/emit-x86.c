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
* @file emit-x86.c
* @brief Support functions to generate (needed) x86 assembly instructions on the fly
* @author Davide Cingolani
* @date May 23, 2014
*/
#include <string.h>
#include <executable.h>
#include <prints.h>

#include "x86.h"
#include "emit-x86.h"
#include <elf/emit-elf.h>


long write_x86_code(function *func, section *text, section *relocation) {
	insn_info *instr;
	insn_info_x86 *x86;
	symbol *sym;
	void *ptr;
	int offset;
	int displ;

	ptr = text->ptr;
	instr = func->insn;

	while(instr != NULL) {
		x86 = &instr->i.x86;

		// handle the relocation
		if(instr->reference && !IS_JUMP(instr)) {
			sym = instr->reference;

			displ = 0;
			if(x86->disp != 0)
				displ = x86->disp_size;
				
			offset = instr->new_addr + x86->opcode_size + displ;
			sym->relocation.offset = offset;

		//	printf("opcode_size= %d, disp_size= %d, span= %d, disp= %llx\n", x86->opcode_size, x86->disp_size, x86->span, x86->disp);

			elf_write_reloc(relocation, sym, offset, sym->relocation.addend);
		}

		// copy the instruction
		memcpy(text->ptr, x86->insn, instr->size);
		text->ptr = (void *)((char *)text->ptr + instr->size);

		instr = instr->next;
	}

	return (long)((char *)text->ptr - (char *)ptr);
}
