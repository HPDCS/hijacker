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
* @file handle-elf.c
* @brief Functions to manipulate already-parsed ELF object files
* @author Davide Cingolani
*/

#pragma once
#ifndef HANDLE_ELF_
#define HANDLE_ELF_

#include <executable.h>
#include <instruction.h>

#define RELOCATE_RELATIVE_32	0
#define RELOCATE_RELATIVE_64	1
#define RELOCATE_ABSOLUTE_32	2
#define RELOCATE_ABSOLUTE_64	3

symbol * find_symbol (char *name);

/**
 * In order to be linkable, new relocation nodes can be created in case
 * genereted instructions have to be referenced.
 *
 * @param sym Symbol descriptor of the symbol that will be referenced to
 * @param insn The pointer to the descritpor of the instruction who need to be relocated
 */
void instruction_rela_node (symbol *sym, insn_info *insn, unsigned char type) ;


void create_rela_node(symbol *sym, long long offset, long addend, unsigned char *secname) ;


/**
 * Given the 'name' of a symbol, it look wheter it exists in the list
 * and, in case, it returns this symbol. Otherwise the funciton will
 * create a new symbol with the specified attributes.
 * Note that the attributes passed are only used if a new symbol has
 * to be created from scratch.
 *
 * @param name A pointer to the string that represents the symbol's name
 * @param type Integer representing the constant for the internal symbol's type
 * @param bind Integer representing the constant for the internal symbol's binding
 * @param size The size in bytes of the symbol, if present
 *
 * @return The pointer to a symbol matching the name requested.
 */
symbol *create_symbol_node(unsigned char *name, int type, int bind, int size);


/**
 * Creates a new function descriptor with name 'name' and its
 * relative symbol. The newly created function is added to the
 * program's code list (at the end) as a global symbol.
 *
 * @param name The buffer pointing to the new name of the function
 * @param insn The pointer to the list of the instruction's list belonging to the function
 *
 * @return The pointer to the new function desciptor
 */
function * create_function_node (char *name, insn_info *insn);


/**
 * Verifies if the passed symbol is a shared.
 * In case the symbol is shared among multiple relocation
 * entries, then a copy of it will be created in order to save
 * the new offset. During the emit phase, each additional copy
 * of the symbol will be skipped but the relative offset
 * added to a new relocation entry whose the symbol refers to.
 *
 * Note: The function will update the list of symbols by adding
 * the possible duplicate.
 *
 * @param sym Symbol descriptor to check
 *
 * @return The symbol descriptor of the new symbol, or the symbol passed
 * in case no sharing happened.
 */
symbol * symbol_check_shared (symbol *sym);


/**
 * Clones the function 'original' into another function descriptor with name 'name'.
 * The whole instructions' list will be clone as well, in order to allow the instrumentation.
 *
 * @param original Pointer to the function's descriptor to copy from
 * @param name Name of the new function
 *
 * @return Pointer to the newly created function's descriptor
 */
function * clone_function_descriptor (function *original, char *name);


/**
 * Switches to the given executable version. If the version passed is grater than the
 * max version available, than a new executable version to instrument is created from scratch.
 * Note that max 256 versions are currently supported.
 *
 * @param version The integer representing the version to switch
 *
 * @return An integer representing the current instrumenting version.
 */
int switch_executable_version (int version);

#endif /* HANDLE_ELF_ */
