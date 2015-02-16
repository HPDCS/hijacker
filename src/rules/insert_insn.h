/*
 * insert_insn.h
 *
 *  Created on: 11/lug/2014
 *      Author: davide
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
int insert_instruction_at (insn_info *target, char *binary, size_t size, int flag, insn_info **insn);


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


int substitute_instruction_with(insn_info *target, char *binary, size_t size, insn_info **insn);


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
