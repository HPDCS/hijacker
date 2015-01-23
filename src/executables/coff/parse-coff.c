#include <stdbool.h>
#include <prints.h>

#include "coff-defs.h"

void coff_create_map(void) {
}


int coff_instruction_set(void) {

	hnotice(1, "Determining instruction set... ");

	// TODO Stub
	hfail();
	return UNRECOG_INSN;
}

bool is_coff(char *path) {

	hnotice(1, "Checking whether '%s' is a COFF executable...", path);

	// TODO: Stub
	hfail();
	return false;
}

