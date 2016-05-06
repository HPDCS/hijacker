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
* @file reverse-x86.h
* @brief Generation of a reverse x86 instruction
* @author Davide Cingolani
* @date July 24, 2014
*/

#pragma once
#ifndef REVERSE_X86_H_
#define REVERSE_X86_H_

#include <instruction.h>
#include <trampoline.h>


void x86_trampoline_prepare(insn_info *target, char *function_name, int where);

/**
 * In order to properly save the stack in the instrumented code
 * it's needed to generate the push instructions by coalescing
 * important data into the minimum required instructions.
 * To do that this auxiliary functions will generate the push
 * instruction bytes that can be written on the instrumente code.
 *
 * @param target The instruction descriptor of the memwrite MOV
 * @param entry Pointer to the trampoline's structure
 *
 */
void push_x86_insn_entry (insn_info *target, insn_entry *entry);


/**
 * Retrieve the information needed to fill the structure <em>insn_entry</em>
 * used by the trampoline module to generate the reverse code.
 *
 * @param insn Instruction descriptor to be parsed
 * @param entry A pointer to the trampoline structure descriptor
 *
 */
void get_x86_memwrite_info (insn_info *insn, insn_entry *entry);


/**
 * Create a new CALL instruction to the reference symbol passed as parameter.
 *
 * @param target The pointer to the instruction target descriptor from which to instert the CALL
 *
 * @return A pointer to the newly created CALL instruction
 */
insn_info * insert_x86_call_instruction (insn_info *target);

#endif /* REVERSE_X86_H_ */
