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
* @file section.c
* @brief Module to handle sections in the Intermediate Representation
* @author Alessandro Pellegrini
* @author Davide Cingolani
* @author Simone Economo
* @date July 13, 2015
*/

#include <string.h>

#include <hijacker.h>
#include <prints.h>
#include <ibr.h>

/**
 * Creates and links a new section descriptor, representing a symbol with a given
 * type, index in the symbol table and payload.
 *
 * @param type Integer constant which represents the type of the section.
 * @param secndx Integer representing the index number of the section in the
 * symbol table included in the executable file.
 * @param first Pointer to a list of sections to which append the new one.
 */
section *add_section(section_type type, int secndx, void *payload, section **first) {
	section *s;

	// [SE] TODO: Verificare se risolve del tutto la ridondanza fra le due funzioni
	// [SE] TODO: Meglio static!
	if (!first) {
		first = &PROGRAM(sections);
	}
	// [/SE]

	// Create and populate the new node
	section *new = (section *)malloc(sizeof(section));
	if(!new){
		herror(true, "Out of memory!\n");
	}
	bzero(new, sizeof(section));

	new->type = type;
	new->index = secndx;
	new->header = sec_header(secndx);
	new->payload = payload;

	if(*first == NULL)
		*first = new;
	else {
		s = *first;
		while(s->next != NULL) {
			s = s->next;
		}
		s->next = new;
	}

	return new;
}


/**
 * Looks for the section with the index specified.
 *
 * @return Returns the pointer to the section found, if any, NULL otherwise.
 */
inline section * find_section(unsigned int idx) {
	section *sec = 0;

	sec = PROGRAM(sections);
	while(sec) {
		if(sec->index == idx)
			break;
		sec = sec->next;
	}

	return sec;
}

section *find_section_by_name(unsigned char *name) {
	section *sec = NULL;

	sec = PROGRAM(sections);
	while(sec) {
		if(sec->name && !strcmp(sec->name, name))
			break;
		else if (!strcmp(sec_name(sec->index), name))
			break;
		sec = sec->next;
	}

	return sec;
}
