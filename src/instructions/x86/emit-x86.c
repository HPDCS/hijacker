
#include <string.h>
#include <executable.h>
#include <prints.h>

#include "x86.h"
#include "emit-x86.h"


long write_x86_code(function *func, section *text, section *reloc) {
	insn_info *insn;
	insn_info *jumpto;
	insn_info_x86 *x86;
	symbol *sym;
	void *ptr;
	int offset;
	int size;
	long long jump_displacement;
	char jump_type;

	ptr = text->ptr;
	insn = func->insn;

	while(insn) {
		x86 = &insn->i.x86;

		// handle the relocation
		if(insn->reference && !IS_JUMP(insn)) {
			sym = (symbol *) insn->reference;

			offset = insn->new_addr + x86->opcode_size;
			sym->relocation.offset = offset;

			elf_write_reloc(reloc, sym, offset, sym->relocation.addend);
		}

		// copy the instruction
		memcpy(text->ptr, x86->insn, insn->size);
		text->ptr += insn->size;

		insn = insn->next;
	}

	return (text->ptr - ptr);
}
