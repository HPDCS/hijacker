#include <stdbool.h>
#include <prints.h>

#include "pe-defs.h"

void pe_create_map(void) {
}

int pe_instruction_set(void) {

	hnotice(1, "Determining instruction set... ");

	// TODO Stub
	hfail();
	return UNRECOG_INSN;
}

bool is_pe(char *path) {

	hnotice(1, "Checking whether '%s' is a PE executable...", path);

	// TODO: Stub
	hfail();
	return false;
}

