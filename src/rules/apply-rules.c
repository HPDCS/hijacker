
#include <stdio.h>
#include <string.h>

#include <executable.h>
#include <elf/reverse-elf.h>
#include <hijacker.h>
#include <prints.h>

#include "insert_insn.h"

// FIXME: only debug!
static int count = 14;

/**
 * Debug function that insert siples NOPs
 */
static void add_nop (function *func, insn_info *insn) {
	if(!count--) {
		char bytes[15];

		// add NOP instruction at this point
		bzero(bytes, 15);
		bytes[0] = 0x90;
		bytes[1] = 0xff;

		// call the function 'insert_instrution_at' to create
		// a new node and inserting it into the instructions chain
		insert_instruction_at(func, insn, bytes, 2, INSERT_AFTER);


		// and then will substitute the newly created NOP with a multi-byte NOP
		bytes[0] = 0x66;
		bytes[1] = 0x0f;
		bytes[2] = 0x1f;
		bytes[3] = 0x84;

		// call the function 'insert_instrution_at' to create
		// a new node and inserting it into the instructions chain
		substitute_instruction_with(func, insn->next, bytes, 9);
	}
}

/**
 * Given a rule, applies it by calling the correspondent function
 */
// TODO: per ora inerisce a caso una NOP all'intero del codice chiamando
// la funzione 'insert_instrucion' che si preoccupa di aggiungere un nodo istruzione
// aggiornando i puntatori
void apply_rules() {
	function *func;
	insn_info *insn;

	hprint("Start applying rules...\n");

	reverse_monitor();
}
