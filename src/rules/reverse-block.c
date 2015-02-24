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
* @file reverse-block.c
* @brief
* @author Davide Cingolani
* @date July, 11 2014
*/

#include "instructions.h"
#include "trampoline.h"

/**
 * Check the whole code looking for all the MOV instructions who access
 * the memory handling them by calling the 'trampoline' module which, in turn,
 * saves on the current stack the values and generates the reversing code.
 *
 * @param insn The current insntruction descriptor to be checked
 */
void check_memwrite_instructions(insn_info *insn) {
	// check if the passed instruction is a memwrite one
	// otherwise will exit immediatly
	if (IS_MEMWR(insn)) {

		// if the current instruction accesses the memory
		// then is needed to save the stack and call the
		// trampoline module in order to generate the reverse code


		// Save the relevant information neede by the 'trampoline'
		// module by pushing them into the current stack
		insn_entry entry;
		entry.

		insert_instruction_at(func, insn, bytes, size, INSERT_BEFORE);
	}
}
