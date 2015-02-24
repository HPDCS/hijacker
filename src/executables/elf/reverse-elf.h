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
* @file reverse-elf.h
* @brief Code needed by the 'trampoline' module to support reverse code generation.
* @author Davide Cingolani
* @date July 24, 2014
*/


#ifndef REVERSE_ELF_H_
#define REVERSE_ELF_H_

#include <instruction.h>
#include <trampoline.h>

#include <x86/reverse-x86.h>

/**
 * Prior to call the <em>trampoline</em> module who generates the reverse code, it is needed
 * to push the <em>insn_entry</em> structure used by the trampoline into the current stack.
 *
 * @param func Pointer to the function to which the memwrite instruction belongs
 * @param target Pointer to the descriptor of the write MOV instruction to be instrumented
 * @param entry Pointer to the <em>insn_entry</em> structure needed by the trampoline
 */
//void push_insn_entry (function *func, insn_info *target, insn_entry *entry);

/**
 * Retrieve from the instruction descriptor the information needed to fill up
 * the <em>insn_entry</em> structure.
 *
 * @param insn Pointer to the target instruction descriptor
 * @param Non-null pointer to the trampoline structure to be filled
 */
//void get_memwrite_info (insn_info *insn, insn_entry *entry);


void prepare_trampoline_call (insn_info *target, symbol *reference);

#endif /* REVERSE_ELF_H_ */
