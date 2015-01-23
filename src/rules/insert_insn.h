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


/**
 * A new instruction node can be created starting from an array of bytes which represents
 * its raw content. To get the instruction descriptor used by hijacker, this function will
 * parse the content and thus generate the instruction node.
 *
 * @param bytes The array of char representing the raw content of the instruction
 * @param size The size of the array of bytes
 *
 * @return An instruction descriptor representing the new instruction node
 */
insn_info * parse_instruction_bytes (char *bytes, size_t size);


/**
 * Adds a new instruction node in the function instructions chain.
 * Creates a new instruction descriptor and adds it to the corresponding instructions chain
 * updating all the pointers.
 *
 * @param func Function pointer descriptor to which the instruction <em>offset</em> belongs
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
insn_info * insert_instruction_at (function *func, insn_info *offset, char *bytes, size_t num_bytes, int flag);
// insn_info * insert_instruction_at (function *func, insn_info *offset, insn_info *insn, int flag);


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
 * @param func Function descriptor to which target instruction belongs to.
 * @param target Target instruction descriptor pointer.
 * @param bytes Pointer to the opcode that will be substituted to the target instruction's one
 * @param num_bytes Size of the bytes provided.
 */
void substitute_instruction_with(function *func, insn_info *target, char *bytes, size_t num_bytes);

/**
 * Adds a new CALL instruction the the rest of the code in the parsed ELF.
 *
 * @param sym The pointer to the descriptor of symbol to which the call refers
 *
 * @return The pointer to the newly created CALL instruction descriptor
 */
insn_info * add_call_instruction (symbol *sym);


#endif /* INSERT_INSN_H_ */
