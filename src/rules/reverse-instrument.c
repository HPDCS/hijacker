#include <stdio.h>
#include <string.h>

#include <prints.h>
#include <executable.h>
#include <instruction.h>
#include <elf/reverse-elf.h>
#include <elf/handle-elf.h>
#include <compile.h>

#include "trampoline.h"
#include "insert_insn.h"

static void compile_needed_modules () {


}

/**
 * This rule will instrument the original code in order to provide
 * the reverse computation support. For each instruction of the original
 * code who writes on memory, the structure 'insn_entry' is packed into
 * a sequence of push instructions before the target MOV. Finally a CALL
 * instruction to the 'trampoline' module is added, agian, before the target
 * MOV, which generetes the reverse code.
 *
 * To provide suopport for the linking stage of the module, a new external
 * undefined symbol 'trampoline' is added to the original code.
 *
 * The module is then compiled to be further linked with the rest of code.
 *
 * Note: this function must be called only once.
 */
void reverse_trampoline () {
	insn_entry *entry;
	insn_info *insn;
	insn_info *call;
	function *func;
	symbol *trampoline;
	int size;

	hnotice(1, "Instrument trampoline module\n");

	// Stage 1: prepare module symbol and object (.o file)
	// look for, or create, the new 'trampoline' symbol to be linked
	trampoline = PROGRAM(symbols);
	while (trampoline) {
		if (!strcmp(trampoline->name, "trampoline")) break;
		trampoline = trampoline->next;
	}

	// ensure that even though the function is called more than once
	// no duplicate symbols or useless compiling would be made
	if (!trampoline) {
		// no symbol are found, create it
		trampoline = create_symbol_node("trampoline", SYMBOL_UNDEF, STB_GLOBAL, 0);

		// if no symbol was found meas that neither was compiled the module
		// thus, compile 'trampoline64.S' module
		hnotice(4, "Compiling trampoline module...\n");

		// TODO: path to module to environmental variabile
		compile("./src/rules/trampoline64.S", "-c");

		hnotice(4, "Compiling reverse-generator module...\n");
		compile("./src/rules/reverse-generator.c", "-c", "-I", "./src/");

		hsuccess();
	}

	// Stage 2: look for the memwrite instructions
	// Iterate over all the functions and all over its instructions
	func = PROGRAM(code);
	while(func) {
		hnotice(1, "Scanning function '%s'...\n", func->name);

		insn = func->insn;
			while(insn) {

				// check if the instruction writes on non-stack memory and in case
				// will instrument the code in order to generate the reverse code
				hnotice(2, "Check if instruction at <%#08lx> writes on memory...\n", insn->new_addr);

				if(IS_MEMWR(insn) && !IS_STACK(insn)) {

					hnotice(3, "MEMWRITE instruction detected!\n");
					// if so, then will instrument the code by saving into the current
					// stack the value of the 'trampoline' structure needed by 'trampoline'
					// module to generate the reverse code

					prepare_trampoline_call(insn, trampoline);

					//entry = (insn_entry *) malloc(sizeof(insn_entry));
					//get_memwrite_info(insn, entry);


					//push_insn_entry(func, insn, entry);
					//create_call_instruction(func, insn, trampoline);
					//create_rela_node(trampoline, insn);
				}

				insn = insn->next;
			}

		func = func->next;
	}

	// Stage 3: link original code together with the compiled module
	// this must be done only to the end of the execution
	hprint("trampoline module correctly instrumented\n");
	hsuccess();
}


/*void link_module () {
	// Stage 3: link the original code together with the compiled module
	hnotice(1, "Linking trampoline module to the original code...\n");
	link("-r", "hijacked.o", "trampoline64.o", "reverse-generator.o", "-o", "final.o");
	hsuccess();
}*/
