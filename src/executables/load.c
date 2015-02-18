#include <stdio.h>

#include <executable.h>
#include <hijacker.h>
#include <prints.h>



static void check_executable(char *path) {

	// First, check if the file exists
	if(!file_exists(path)) {
		herror(true, "Unable to open '%s'\n", path);
	}

	// Then, try some magic to determine what kind of file it is
	if(is_elf(path)) {
		PROGRAM(type) = EXECUTABLE_ELF;
		return;
	}

	if(is_coff(path)) {
		PROGRAM(type) = EXECUTABLE_COFF;
		return;
	}

	if(is_pe(path)) {
		PROGRAM(type) = EXECUTABLE_PE;
		return;
	}

	// Too bad...
	herror(true, "Unrecognized executable format for '%s'\n", path);
}



static void check_instruction_set(void) {
	bool recognized = false;
	
	// Switch on file type
	switch(PROGRAM(type)) {

		case EXECUTABLE_ELF:

			PROGRAM(insn_set) = elf_instruction_set();
			if(PROGRAM(insn_set) != UNRECOG_INSN) {
				recognized = true;
			}
			break;

		case EXECUTABLE_COFF:

			PROGRAM(insn_set) = coff_instruction_set();
			if(PROGRAM(insn_set) != UNRECOG_INSN) {
				recognized = true;
			}
			break;

		case EXECUTABLE_PE:

			PROGRAM(insn_set) = pe_instruction_set();
			if(PROGRAM(insn_set) != UNRECOG_INSN) {
				recognized = true;
			}
			break;

		default:
			herror(true, "Internal error at '%s', line '%d'\n", __FILE__, __LINE__);
	}

	if(!recognized) {
		herror(true, "Unrecognized instruction set");
	}
}


static void create_map() {

	hprint("Creating program map...\n");

	// Switch on file type
	switch(PROGRAM(type)) {

		case EXECUTABLE_ELF:

			elf_create_map();
			break;

		case EXECUTABLE_COFF:

			coff_create_map();
			break;

		case EXECUTABLE_PE:

			pe_create_map();
			break;

		default:
			hinternal();
	}

}



/****************************************/


void add_section(int type, int secndx, void *payload) {
	section *s;

	// Create and populate the new node
	section *new = (section *)malloc(sizeof(section));
	new->type = type;
	new->index = secndx;
	new->header = sec_header(secndx);
	new->payload = payload;
	new->next = NULL;

	if(PROGRAM(sections) == NULL)
		PROGRAM(sections) = new;
	else {
		s = PROGRAM(sections);
		while(s->next != NULL) {
			s = s->next;
		}
		s->next = new;
	}
}


/*section *get_section_type(int type) {
	section *sec, **first;

	first = (section **)malloc(sizeof(void *) * 4);

	first = curr = 0;
	sec = PROGRAM(sections);
	while(sec){
		if(sec->type == type){
			if(!first) first = curr = sec;
			else curr->next = sec;
			curr =
		}
		sec = sec->next;
	}

	return first;
}*/

void load_program(char *path) {

	hprint("Loading '%s'...\n", path);

	// Determine what type of executable are we handling
	check_executable(path);

	// Determine which instruction set is the program
	check_instruction_set();

	// Create the memory map
	create_map();

	// Process rules
	// TODO: ci possono essere più regole sullo stesso simbolo
}


