/*
 * reverse-x86.h
 *
 *  Created on: 24/lug/2014
 *      Author: davide
 */

#ifndef REVERSE_X86_H_
#define REVERSE_X86_H_

#include <instruction.h>
#include <trampoline.h>


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
