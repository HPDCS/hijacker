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
* @file insert_insn.h
* @brief Module to add instructions in the Intermediate Representation
* @author Davide Cingolani
* @date July, 11 2014
*/

#ifndef INSERT_INSN_H_
#define INSERT_INSN_H_

#include <executable.h>
#include <instruction.h>

#define INSERT_BEFORE	0
#define INSERT_AFTER	1
#define SUBSTITUTE	2


/**
 * A new instruction node can be created starting from an array of bytes which represents
 * its raw content. To get the instruction descriptor used by hijacker, this function will
 * parse the content and thus generate the instruction node.
 *
 * @param bytes The array of char representing the raw content of the instruction
 * @param pos Current position of the file pointer of 'bytes' stream
 *
 * @return An instruction descriptor representing the new instruction node
 */
//insn_info * parse_instruction_bytes (char *bytes, long unsigned int pos);


/**
 * Adds a new instruction node in the function instructions chain.
 * Creates a new instruction descriptor and adds it to the corresponding instructions chain
 * updating all the pointers.
 *
 * @param target Instruction descriptor (<em>insn_info</em>) that represents the instructions
 * referenced to by the rules at which apply it. The <em>flag</em> parameter is used in order
 * to decide if the new node will be added before or after the instruction pointed by <em>offset</em>
 * @param bytes Pointer to a buffer of bytes representing the instruction itself in the machine dependent format.
 * @param num_bytes Instruction's length (hence of the <em>bytes</em> parameter).
 * @param flag A flag [INSERT_BEFORE or INSERT_AFTER] indicating where insert the new node with respect to the
 * reference instruction point <em>offset</em>.
 *
 * @return The pointer to the descriptor of the newly insterted instruction
 */
//insn_info * insert_instruction_at (function *func, insn_info *offset, char *bytes, size_t num_bytes, int flag);
int insert_instructions_at(insn_info *target, unsigned char *binary, size_t size, int flag, insn_info **insn);


/**
 * Given a buffer of binary code, this function will translates them into
 * instruction descriptor for the internal binary reprsentation, and adds
 * them to it until the buffer is over.
 *
 * @parm target Pointer to the instruction descriptor to which perform the insertion
 * @param binary Pointer to the buffer of bytes containing the binary code
 * @param size The size of the whole buffer
 * @param flag A flag value [INSERT_BEFORE or INSERT_AFTER] indicating where to insert the content of the buffer
 *
 * @return The pointer to the last inserted instruction descriptor
 */
//int insert_binary_at(insn_info *target, char *binary, size_t size, int flag, insn_info **insn);


/**
 * Substitutes one instruction with another.
 * This function substitutes the instruction pointed to by the <em>target</em> instruction descriptor with
 * the bytes passed as argument as well. After new instruction is swapped, all the others are accordingly shifted to
 * the relative offset (positive or negative) introduced by the difference between the two sizes.
 * Note: This function will call the disassembly procedure in order to correctly parse the instruction bytes passed as
 * argument. This is a fundamental step to retrieve instruction's metadata, such as jump destination address,
 * displacement offset, opcode size and so on. Without these information future emit step will fail to correctly
 * relocates and links jump instructions together.
 *
 * @param target Target instruction descriptor pointer.
 * @param bytes Pointer to the opcode that will be substituted to the target instruction's one
 * @param num_bytes Size of the bytes provided.
 */
//void substitute_instruction_with(function *func, insn_info *target, char *bytes, size_t num_bytes);
//int substitute_instruction_with(insn_info *target, insn_info *insn);


int substitute_instruction_with(insn_info *target, unsigned char *binary, size_t size, insn_info **insn);


/**
 * Adds a new CALL instruction the the rest of the code in the parsed ELF.
 *
 * @param target Pointer to the pivot instruction descriptor to which adds the CALL
 * @param functions Pointer to the buffer of the function's name to be called
 * @param where Integer constant representing where to add the CALL wrt 'target'
 *
 * @return The pointer to the newly created CALL instruction descriptor
 */
void add_call_instruction (insn_info *target, char *function, int where);


#endif /* INSERT_INSN_H_ */
