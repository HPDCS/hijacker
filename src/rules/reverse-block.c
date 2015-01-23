#include "instructions.h"
#include "monitor.h"

/**
 * Check the whole code looking for all the MOV instructions who access
 * the memory handling them by calling the 'monitor' module which, in turn,
 * saves on the current stack the values and generates the reversing code.
 * 
 * @param insn The current insntruction descriptor to be checked
 */
void check_memwrite_instructions (insn_info *insn) {
	// check if the passed instruction is a memwrite one
	// otherwise will exit immediatly
	if (IS_MEMWR(insn)) {
		
		// if the current instruction accesses the memory
		// then is needed to save the stack and call the
		// monitor module in order to generate the reverse code
		
		
		// Save the relevant information neede by the 'monitor'
		// module by pushing them into the current stack
		insn_entry entry;
		entry.
		
		insert_instruction_at(func, insn, bytes, size, INSERT_BEFORE);
	}
}
