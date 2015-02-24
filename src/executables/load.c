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
* @file load.c
* @brief Operations to load an object file
* @author Alessandro Pellegrini
* @author Davide Cingolani
*/

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


