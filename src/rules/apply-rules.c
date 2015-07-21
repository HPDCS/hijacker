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
* @file apply-rules.c
* @brief Module to iteratively apply xml-specified rules on the Intermediate Representation
* @author Davide Cingolani
*/

#include <stdio.h>
#include <string.h>
#include <libgen.h>

#include <executable.h>
#include <elf/reverse-elf.h>
#include <elf/handle-elf.h>
#include <hijacker.h>
#include <prints.h>
#include <compile.h>

#include "insert_insn.h"
#include "rules.h"
#include "apply-rules.h"

/**
 * The Inject tag simply identifies a file that has to be compiled togeter
 * with the remainder of the program. Therefore, once the filename is retrieved,
 * this function simply compile and mark as 'to be linked' the resulting ELF.
 *
 * @param tagInject Pointer to the Ibject XML tag descriptor
 */
static void apply_rule_link (char *filename) {
	//~char *objname;
	//~char *path;

	hnotice(2, "Entering Inject scope: compiling and linking module '%s'\n", filename);

	// Note that 'filename' is the assembly source
	// therefore it must be firstly translated into
	// a binary file in order to pass it to disassemble function

	// Check if the file really exists and compile the assmbly into the 'bin' file
	//~len = strlen(filename) + 1;

	//~objname = malloc(len * sizeof(char));
	//~strcpy(objname, filename);
	//~objname[len-1] = 'o';

	//~path = malloc(64 * sizeof(char));
	//~bzero(path, 64 * sizeof(char));
	//~strcpy(path, TEMP_PATH);
	//~strcat(path, objname);

	//~hnotice(6, "Compiling file in '%s'\n", path);
	if(!file_exists(filename)) {
		herror(true, "The XML rules file has specified a file that does not exists!\n");
	}

	// Just compile the given module's source.
	// The resulting object file will be linked in the final stage.
	compile(filename, "-c", "-o", "current.o");

	if(file_exists("incremental.o")) {
		link("-r", "incremental.o", "current.o", "-o", "__incremental.o");
		unlink("current.o");
		unlink("incremental.o");
		rename("__incremental.o", "incremental.o");
	} else {
		rename("current.o", "incremental.o");
	}
}


/**
 * Retrieve the content from the file name passed as argument and
 * injects its content into the current entity (Function or Instruction),
 * according with the rule's specification.
 *
 * @param filename Pointer to the file string name
 */
static void apply_rule_inject (char *filename, insn_info *target, int where) {
	FILE *fp;
	int fsize;
	unsigned char *fcontent;
	insn_info *insn;

	// Note that 'filename' is the assembly source
	// therefore it must be firstly translated into
	// a binary file in order to pass it to disassemble function

	// Compile the assembly into the 'bin' file
	hnotice(6, "Compiling assembly file into binary file 'bin'\n");

	// Check the file actually exists
	if(!file_exists(filename)) {
		herror(true, "The XML rules file has specified an inject file that does not exists!\n");
	}
	compile(filename, "-c", "-o", "obj");
	execute("objcopy", "-O", "binary", "obj", "bin");

	// Open the file in reading mode
	hnotice(6, "Opening assembly binary file 'bin'\n");
	fp = fopen("bin", "r");

	// Get the file size
	fseek(fp, 0, SEEK_END);
	fsize = ftell(fp);
	rewind(fp);

	// Allocate the memory buffer for the file
	fcontent = malloc(sizeof(char) * fsize);
	if(!fcontent) {
		execute("rm", "obj");
		execute("rm", "bin");
		herror(true, "Out of memory!\n");
	}

	// Copy the file into the buffer
	if(fread(fcontent, 1, fsize, fp) != (size_t)fsize) {
		execute("rm", "obj");
		execute("rm", "bin");
		herror(true, "Unable to read the file!\n");
	}


	// TODO: verificare la correttezza del contenuto rispetto alle specifiche (architettura, sintassi, convenzioni, etc.)

	if(where == SUBSTITUTE)
		substitute_instruction_with(target, fcontent, fsize, &insn);
	else
		insert_instructions_at(target, fcontent, fsize, where, &insn);

	fclose(fp);
	execute("rm", "obj");
	execute("rm", "bin");
	free(fcontent);

	hsuccess();
}


/**
 * Creates and adds to the text section a new CALL instruction to the
 * referenced symbol name.
 *
 * @param tagCall Pointer to the Call tag
 */
static void apply_rule_addcall (Call *tagCall, insn_info *target) {
	int where;

	if(tagCall->where) {
		if(!strcmp((const char *)tagCall->where, ATTRIB_WHERE_BEFORE))
			where = INSERT_BEFORE;
		else if(!strcmp((const char *)tagCall->where, ATTRIB_WHERE_AFTER))
			where = INSERT_AFTER;
		else // Default
			where = INSERT_BEFORE;
	} else {
		// Default value
		where = INSERT_BEFORE;
	}

	// Check the AddCall arguments:
	if(tagCall->arguments) {

		// 'target' means that the instrumentation has
		// build up the insn_entry stack structure
		// embedding into it a pointer to the functions
		// to be called at runtime.
		if(!strcmp((const char *)tagCall->arguments, "target")){
			hnotice(4, "Specified a 'target' argument to '%s' function, preparing the trampoline structure\n", tagCall->function);

			// Prepare the trampoline structure on the stack
			trampoline_prepare(target, (unsigned char *)tagCall->function, where);

			// Creates and adds a new CALL to the trampoline function with respect to the 'target' one
			//add_call_instruction(target, (unsigned char *)"trampoline", where);
		}
	} else {
		// Creates and adds a new CALL  with respect to the 'target' one
		add_call_instruction(target, (unsigned char *)tagCall->function, where, &target);
	}

	hnotice(2, "Added call instruction to symbol '%s'\n", tagCall->function);
}


/**
 * Given a XML instruction tag, it will apply the relative rule to the current
 * internal binary representation of the ELF file.
 *
 * @param tagInstruction Pointer to the XML instruction tag maintaining the rule
 *
 * @return The number of instrumented instructions
 */
static int apply_rule_instruction(Executable *exec, Instruction *tagInstruction, function *func) {
	int tag;
	int count;
	insn_info *insn;
	Assembly *tagAssembly;
	Call *tagCall;

	(void)exec;

	// Since the current function will be instrumented
	// we must to create a new function descriptor by cloinig
	// the current one.
/*	if(func->symbol->version != PROGRAM(version)) {
		// If the version of the symbol is zero, then
		// the function is not yet an instrumented clone
		// and we do clone it
		sprintf(name, "%s-%s", func->name, exec->suffix);
		func = clone_function_descriptor(func, name);
	}*/

	insn = func->insn;
	count = 0;

	hnotice(2, "Entering Instruction scope; searching for instruction of type %d\n", tagInstruction->flags);
	while(insn) {
		hnotice(5, "Checking instruction at <%#08llx>\n", insn->new_addr);

		// Check whether the instruction's type match to the rule
		if (insn->flags & tagInstruction->flags) {
			// If this is the case, the rules applies.
			hnotice(3, "Instruction matching the rule specification is found:\n");
			hnotice(4, "Instrumenting '%s' at %#08llx...\n", insn->i.x86.mnemonic, insn->new_addr);

			// Increment the counter of instrumented instructions
			count++;


			// Instruction tags may be composed of several Assembly tags
			for(tag = 0; tag < tagInstruction->nAssembly; ++tag) {
				// Retrieve the next assembly tag and process it
				hnotice(2, "Assembly tag met, applying the rule\n");
				tagAssembly = tagInstruction->assembly[tag];


				hnotice(3, "Parse instruction bytes '%s'\n...", tagAssembly->instruction);
				// TODO: chiamare la funzione parse_insn_bytes()
				// TODO: chiamare la funzione insert_instruction_at()
			}

			// Check if the Instruction tag has a Call node
			if(tagInstruction->call) {
				tagCall = tagInstruction->call;
				apply_rule_addcall(tagCall, insn);
			}

			// Check injectBefore attribute
			if(tagInstruction->before) {
				apply_rule_inject((char *)tagInstruction->before, insn, INSERT_BEFORE);
			}

			// Check injectAfter attribute
			if(tagInstruction->after) {
				apply_rule_inject((char *)tagInstruction->after, insn, INSERT_AFTER);
			}

			// Check replace attribute
			if(tagInstruction->replace) {
				apply_rule_inject((char *)tagInstruction->replace, insn, SUBSTITUTE);
			}
		}

		insn = insn->next;
	}

	if(!count) {
		hnotice(2, "No instruction that matches the rule is found\n");
	}

	return count;
}


/**
 * Given a XML function tag, it will apply the relative rule to the current
 * internal binary representation of the ELF file. A function tag define the
 * instrument scope for embraced sub-tags, therefore a single function likely
 * has different instruction tags beneath.
 * Once the function has been identified, the instrumentation process of the
 * other sub-tags will take place.
 *
 * @param tagFunction Pointer to the XML function tag maintaining the rule
 *
 * @return The number of the instrumented instructions
 */
static int apply_rule_function (Executable *exec, Function *tagFunction) {
	function *func;
	int tag;
	int count;

	Instruction *tagInstruction;
	Call *tagCall;
	count = 0;

	hnotice(2, "Entering Function scope: searching '%s' function", tagFunction->name);

	func = PROGRAM(code);
	while(func) {
		// Look for the right function to which to apply the rule
		if(!strcmp((const char *)func->name, (char *)tagFunction->name)) {
			hnotice(4, "Function matching '%s' the rule name found\n", func->name);

			// Retrieve the sub tags: a function may be composed of
			// several Instruction or Assembly tags

			// Iterates all over the Instruction sub-tags
			for(tag = 0; tag < tagFunction->nInstructions; tag++) {
				// Retrive the next instruction tag and process it
				hnotice(2, "Instruction tag met, applying the rule\n");
				tagInstruction = tagFunction->instructions[tag];
				hnotice(3, "Looking for the instruction with flags %x\n", tagInstruction->flags);
				count += apply_rule_instruction(exec, tagInstruction, func);
			}

			// Check if a Call tag has been specified
			if(tagFunction->call) {
				tagCall = tagFunction->call;
				apply_rule_addcall(tagCall, func->insn);
			}

		}

		func = func->next;
	}

	if(!count) {
		hnotice(2, "No function that matches the rule is found\n");
	}

	return count;
}


/**
 * Given a rule, applies it by calling the correspondent function
 */
void apply_rules(void) {
	function *func;

	int tag;
	int version;
	int instrumented;

	char *module;
	Executable *exec;
	Instruction *tagInstruction;
	Function *tagFunction;

	hprint("Start applying rules...\n");

	// Create a temporary directory to place object files;
	execute("mkdir", "-p", TEMP_PATH);

	// Iterates all over executable versions
	for (version = 0; version < config.nExecutables; version++) {
		hnotice(1, "Executable version %d\n", version);

		// Reset the counter of the overall instrumented instructions
		instrumented = 0;

		// Get the new vesion executable's rules
		exec = config.rules[version];

		// Clone the intermediate binary representation
		// Version 0 is reserved to the original plain copy of the application,
		// which has been previously cloned during the ELF parsing
		switch_executable_version(version);

		// Iterates all over the XML inject tag in the Executable
		for (tag = 0; tag < exec->nInjects; tag++) {
			// Retrive the next inject tag and process it
			hnotice(2, "Inject tag met, applying the rule\n");
			module = (char *)exec->injectFiles[tag];
			hnotice(3, "Looking for the instruction with flags '%s'\n", module);
			apply_rule_link(module);
		}

		// Iterates all over the instructions in the Executable XML tag
		for (tag = 0; tag < exec->nInstructions; tag++) {
			// Retrive the next instruction tag and process it
			hnotice(2, "Instruction tag met, applying the rule\n");
			tagInstruction = exec->instructions[tag];
			hnotice(3, "Looking for the instruction with flags %x\n", tagInstruction->flags);
			func = PROGRAM(code);
			while(func) {
				hnotice(3, "Instrumenting function '%s' <%#08llx>\n", func->symbol->name, func->new_addr);
				instrumented += apply_rule_instruction(exec, tagInstruction, func);
				func = func->next;
			}
		}

		for (tag = 0; tag < exec->nFunctions; tag++) {
			// Retrieve the next function tag and process it
			hnotice(2, "Function tag met, applying the rule\n");
			tagFunction = exec->functions[tag];
			hnotice(3, "Looking for the function '%s'\n", tagFunction->name);
			instrumented += apply_rule_function(exec, tagFunction);
		}

		if (version != 0 && instrumented) {
			// [SE] If some actual instrumentation has been carried out, first update
			// instruction addresses and then recompute jump displacements
			update_instruction_addresses();
			update_jump_displacements();
		}

		hnotice(1, "Instrumentation of executable version %d terminated: %d instructions have been instrumented\n",
			version, instrumented);

		hsuccess();
	}
}
