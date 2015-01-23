/*
 * reverse-x86.h
 *
 *  Created on: 24/lug/2014
 *      Author: davide
 */

#ifndef REVERSE_X86_H_
#define REVERSE_X86_H_

#include <instruction.h>
#include <monitor.h>


/**
 * Retrieve the information needed to fill the structure <em>insn_entry</em>
 * used by the monitor module to generate the reverse code.
 *
 * @param insn Instruction descriptor to be parsed
 * @param entry A pointer to the monitor structure descriptor
 *
 */
void push_insn_entry (function *func, insn_info *target, insn_entry *entry);

/**
 * In order to properly save the stack in the instrumented code
 * it's needed to generate the push instructions by coalescing
 * important data into the minimum required instructions.
 * To do that this auxiliary functions will generate the push
 * instruction bytes that can be written on the instrumente code.
 *
 * @param func Function descriptor in which the MOV instruction is located
 * @param target The instruction descriptor of the memwrite MOV
 * @param entry Pointer to the monitor's structure
 *
 */
void get_x86_memwrite_info (insn_info *insn, insn_entry *entry);


/**
 * Create a new CALL instruction to the reference symbol passed as parameter.
 *
 * @param func The pointer to the function descriptor
 * @param target The pointer to the instruction target descriptor from which to instert the CALL
 *
 * @return A pointer to the newly created CALL instruction
 */
insn_info *insert_x86_call_instruction (function *func, insn_info *target);

#endif /* REVERSE_X86_H_ */
