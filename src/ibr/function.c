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
function *find_func(function *functions, insn_info *instr, insn_address_type type) {
	function *func, *prev;

	func = functions;
	prev = NULL;

	while(func) {

		if (type == NEW_ADDR && func->insn->new_addr > instr->new_addr) {
			break;
		}
    else if (type == ORIG_ADDR && func->insn->orig_addr > instr->orig_addr) {
      break;
    }

		prev = func;
		func = func->next;
	}

	if (!func) {
		return NULL;
	}

	return prev;
}


/**
 * Creates a new function descriptor along with its relative symbol. The newly
 * created function is added to the program's code (at the end) and is associated
 * with a global symbol.
 *
 * @param name Buffer pointing to the new name of the function.
 * @param code Pointer to the instruction list that make up the body of the function.
 *
 * @return Pointer to the new function descriptor.
 */
function *create_function_node(char *name, insn_info *code) {
	function *func, *list;
	symbol *sym;
	insn_info *insn;
	int size;

	size = 0;
	insn = code;
	while(insn) {
		size += insn->size;
		insn = insn->next;
	}

	sym = create_symbol_node((unsigned char *)name, SYMBOL_FUNCTION, SYMBOL_GLOBAL, size);

	func = (function *) malloc(sizeof(function));
	if(!func) {
		herror(true, "Out of memory!\n");
	}
	bzero(func, sizeof(function));

	func->name = (unsigned char *)name;
	func->symbol = sym;
	func->insn = code;

	list = PROGRAM(code);
	while(list->next) {
		list = list->next;
	}

	func->orig_addr = func->new_addr = (list->new_addr + list->symbol->size);
	func->symbol->position = func->orig_addr;
	list->next = func;

	hnotice(4, "New function '%s' created\n", name);

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
static int get_function_size(function *func) {
	insn_info *insn;
	int size;

	if(func == NULL)
		return -1;

	insn = func->insn;
	size = 0;
	while(insn) {
		size += insn->size;
		insn = insn->next;
	}

	return size;
}


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

	if(!func)
		return NULL;

	// Allocates memory for the new descriptor
	clone = (function *) malloc(sizeof(function));
	if(!clone) {
		herror(true, "Out of memory!\n");
	}

	// Copies the original descriptor to the new one
	memcpy(clone, func, sizeof(function));

	// Updates the pointer to instruction list
	clone->insn = clone_instruction_list(func->insn);

  // [SE] Reset other references
  clone->begin_blk = clone->end_blk = clone->source = NULL;
  clone->calledfrom.first = clone->calledfrom.last = NULL;
  clone->callto.first = clone->callto.last = NULL;

	// Updates the symbol pointer (assume that symbols have been already be cloned)
	size = strlen((const char *)func->name) + strlen(suffix) + 2; // one is \0, one is '_'
	name = malloc(sizeof(char) * size);
	bzero(name, size);
	strcpy(name, (const char *)func->name);
	strcat(name, "_");
	strcat(name, suffix);

	size = get_function_size(clone);
	if(size <= 0) {
		hinternal();
	}

	clone->symbol = create_symbol_node((unsigned char *)name, SYMBOL_FUNCTION, SYMBOL_GLOBAL, size);
	clone->name = (unsigned char *)name;

	hnotice(6, "Function '%s' (%d bytes) cloned\n", clone->name, clone->symbol->size);

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
	insn_info *insn;
	symbol *sym;

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
