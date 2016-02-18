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
* @file function.c
* @brief Module to handle functions in the Intermediate Representation
* @author Davide Cingolani
* @author Simone Economo
* @date July 13, 2015
*/

#include <string.h>
#include <strings.h>

#include <hijacker.h>
#include <prints.h>
#include <ibr.h>


/**
 * Seeks the function descriptor associated with a given instruction descriptor.
 * Put differently, gets the function that contains a given instruction.
 *
 * @param instr Pointer to the instruction descriptor.
 *
 * @return Pointer to the function descriptor found, if any, or <em>NULL</em>.
 *
 * @author Simone Economo
 */
function *find_func_from_instr(insn_info *instr, insn_address_type type) {
	function *func, *prev;

	for (func = PROGRAM(v_code)[PROGRAM(version)], prev = NULL; func;
		   prev = func, func = func->next) {
		if (type == NEW_ADDR && func->begin_insn->new_addr > instr->new_addr) {
			return prev;
		}
		else if (type == ORIG_ADDR && func->begin_insn->orig_addr > instr->orig_addr) {
			return prev;
		}
	}

	// if (!func) {
	// 	return NULL;
	// }

	return prev;
}


function *find_func_from_addr(unsigned long long addr) {
	function *func;

	for (func = PROGRAM(v_code)[PROGRAM(version)]; func; func = func->next) {
		if (func->begin_insn->orig_addr <= addr
		 && func->begin_insn->orig_addr + func->symbol->size > addr) {
			return func;
		}
	}

	return NULL;
}


/**
 * Creates a new function descriptor along with its relative symbol. The newly
 * created function is added to the program's code (at the end) and is associated
 * with a global symbol.
 *
 * @author Davide Cingolani
 *
 * @param name Buffer pointing to the new name of the function.
 * @param code Pointer to the instruction list that make up the body of the function.
 *
 * @return Pointer to the new function descriptor.
 */
function *function_create_from_insn(char *name, insn_info *code) {
	function *func, *curr;
	symbol *sym;
	insn_info *instr;
	section *sec;

	size_t size;

	size = 0;
	for (instr = code; instr; instr = instr->next) {
		size += instr->size;
	}

	func = (function *) calloc(sizeof(function), 1);

	func->name = (char *) malloc(strlen((const char *) name) + 1);
	strcpy(func->name, name);

	func->begin_insn = code;

	for (curr = PROGRAM(v_code)[PROGRAM(version)]; curr->next; curr = curr->next);

	sec = curr->symbol->sec;
	sec->sym->size += size;

	sym = symbol_create(name, SYMBOL_FUNCTION, SYMBOL_GLOBAL, sec, size);
	func->symbol = sym;
	sym->func = func;

	func->orig_addr = func->new_addr = (curr->new_addr + curr->symbol->size);
	func->symbol->offset = func->orig_addr;

	curr->next = func;

	hnotice(4, "New function '%s' created\n", name);

	return func;
}

// FIXME: unire le funzionalità di parse_instruction_bytes() come catena di istruzioni e
// la funzioe create_function_node()!!!
/**
 * Create a function starting from an array of raw bytes that represents
 * its instructions. The returned function description will be filled
 *
 *
 */
function *function_create_from_bytes(char *name, unsigned char *code, size_t size) {
	insn_info *insn, *first;
	function *func;
	unsigned long long pos;

	first = calloc(sizeof(insn_info), 1);
	insn = first;
	pos = 0;

	func = function_create_from_insn(name, first);
	insn->new_addr = func->new_addr;

	// Parse the instruction bytes provided in order to create a chain of
	// instructions to append to the newly-created function

	// This will create the instruction chain
	while(pos < size) {
		parse_instruction_bytes(code, &pos, &insn);

		insn->orig_addr += pos;
		insn->new_addr += pos;

		insn->next = calloc(sizeof(insn_info), 1);

		insn->next->new_addr = insn->new_addr;
		insn->next->orig_addr = insn->orig_addr;
		insn = insn->next;
	}

	return func;
}

/**
 * Computes the size in bytes of a function by summing up the length of all the
 * instruction in its body.
 *
 * @param func Pointer to the function descriptor whose size has to be computed.
 *
 * @return Size in bytes of the passed function.
 */
// static int get_function_size(function *func) {
// 	insn_info *insn;
// 	int size;

// 	if(func == NULL)
// 		return -1;

// 	insn = func->begin_insn;
// 	size = 0;
// 	while(insn) {
// 		size += insn->size;
// 		insn = insn->next;
// 	}

// 	return size;
// }


/**
 * Clones a single function, producing a new function descriptor whose name
 * is the concatenation of the original name and a suffix passed as parameter.
 * The list of instructions that make up its body is cloned as well.
 *
 * @param func Pointer to the function descriptor to clone.
 * @param suffix Buffer pointing to the suffix.
 *
 * @return Pointer to the clone function descriptor.
 */
function * clone_function (function *func, char *suffix) {
	function *clone;
	char *name;
	int size;

	if (!func) {
		return NULL;
	}

	// Allocates memory for the new descriptor
	clone = (function *) calloc(sizeof(function), 1);

	// Copies the original descriptor to the new one
	memcpy(clone, func, sizeof(function));

	// Updates the pointer to instruction list
	clone->begin_insn = clone_instruction_list(func->begin_insn);

	// Reset some fields
	clone->begin_blk = clone->end_blk = clone->source = NULL;
	clone->calledfrom.first = clone->calledfrom.last = NULL;
	clone->callto.first = clone->callto.last = NULL;

	// Compose the function name
	size = strlen((const char *)func->name) + strlen(suffix) + 2; // one is \0, one is '_'
	name = malloc(sizeof(char) * size);
	bzero(name, size);
	strcpy(name, (const char *)func->name);
	strcat(name, "_");
	strcat(name, suffix);

	clone->name = (unsigned char *)name;

	// FIXME: E' realmente necessario?
	// size = get_function_size(clone);
	// if (size <= 0) {
	// 	hinternal();
	// }

	// Create a new symbol
	clone->symbol = symbol_create(name, func->symbol->type, func->symbol->bind,
		func->symbol->sec, size);

	clone->symbol->func = clone;

	// hnotice(4, "Function '%s' (%d bytes) cloned\n", clone->name, clone->symbol->size);

	return clone;
}


/**
 * Clone the whole function list of the internal representation. This is done
 * in order to support multi-versioning of executable and object files.
 * Cloning the function means to clone their instructions as well.
 *
 * @return Pointer to the first function descriptor of the clone list.
 */
function *clone_function_list(function *func, char *suffix) {
	function *clone, *head;

	if(!func)
		return NULL;

	head = clone = clone_function(func, suffix);
	func = func->next;

	while(func) {
		clone->next = clone_function(func, suffix);
		clone = clone->next;
		func = func->next;
	}

	return head;
}


// FIXME: unire le funzionalità di parse_instruction_bytes() come catena di istruzioni e
// la funzioe create_function_node()!!!
/**
 * Create a function starting from an array of raw bytes that represents
 * its instructions. The returned function description will be filled
 *
 *
 */
/*function *create_function(char *name, unsigned char *code, size_t size) {
	insn_info *insn, *first;
	function *func;
	unsigned long long pos;

	first = calloc(sizeof(insn_info), 1);
	if(first == NULL) {
		abort();
	}

	insn = first;
	pos = 0;

	func = create_function_node(name, first);
	insn->new_addr = func->new_addr;

	// Parse the instruction bytes provided in order to create a chain of
	// instructions to append to the newly created function

	// This will create the instrucion chain
	while(pos < size) {

		parse_instruction_bytes(code, &pos, &insn);

		insn->orig_addr += pos;
		insn->new_addr += pos;

		insn->next = calloc(sizeof(insn_info), 1);

		insn->next->new_addr = insn->new_addr;
		insn->next->orig_addr = insn->orig_addr;
		insn = insn->next;
	}

	return func;
}*/
