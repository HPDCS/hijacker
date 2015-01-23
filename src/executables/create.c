
#include <stdlib.h>

#include <hijacker.h>
#include <prints.h>

void output_object_file(char *pathname, int flags) {
	hprint("Generating the new object file...\n");

	// Switch on file type
	switch(PROGRAM(type)) {

	case EXECUTABLE_ELF:

		elf_generate_file(pathname, flags);
		break;

	case EXECUTABLE_COFF:

		break;

	case EXECUTABLE_PE:

		break;

	default:
		hinternal();
	}
}
