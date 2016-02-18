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


const char *section_type_str[] = {
	"NULL", "CODE", "SYMBOLS", "NAMES", "RELOC", "TLS", "RAW"
};


size_t section_id(size_t nextid, bool update) {
	static size_t id = 0;

	if (nextid > id && update == true) {
		id = nextid;
	}

	return (update == true ? id : id++);
}


section *section_create(char *name, section_type type, void *payload) {
	section *sec;

	sec = (section *) calloc(sizeof(section), 1);

	sec->name = (char *) malloc(strlen((const char *) name) + 1);
	strcpy(sec->name, name);

	sec->type = type;
	sec->payload = payload;
	sec->index = section_id(0, false);

	sec->sym = symbol_create(name, SYMBOL_SECTION, SYMBOL_LOCAL, sec, 0);

	section_append(sec, &PROGRAM(sections)[PROGRAM(version)]);

	hnotice(3, "New %s section '%s' (%d) has been created from scratch\n",
		section_type_str[sec->type], sec->name, sec->index);

	return sec;
}

section *section_create_from_ELF(size_t index, section_type type) {
	section *sec;

	sec = (section *) calloc(sizeof(section), 1);

	sec->name = sec_name(index);
	sec->type = type;
	sec->payload = sec_content(index);

	// TODO: Check for special section index values!
	sec->index = section_id(index, true);

	sec->offset = sec_field(index, sh_offset);
	sec->header = sec_header(index);

	// NOTE: We don't create any symbol, since we expect it to be
	// done in a separate step

	section_append(sec, &PROGRAM(sections)[PROGRAM(version)]);

	hnotice(3, "New %s section '%s' (%d) has been created from ELF\n",
		section_type_str[sec->type], sec->name, sec->index);

	return sec;
}

/**
 * Creates and links a new section descriptor, representing a symbol with a given
 * type, index in the symbol table and payload.
 *
 * @param type Integer constant which represents the type of the section.
 * @param secndx Integer representing the index number of the section in the
 * symbol table included in the executable file.
 * @param first Pointer to a list of sections to which append the new one.
 */
void section_append(section *sec, section **head) {
	section *curr;

	if (head == NULL) {
		hinternal();
	}

	if (*head == NULL) {
		*head = sec;
	} else {
		curr = *head;

		while (curr->next) {
			curr = curr->next;
		}

		curr->next = sec;
	}
}


/**
 * Looks for the section with the index specified.
 *
 * @return Returns the pointer to the section found, if any, NULL otherwise.
 */
inline section *find_section(unsigned int index) {
	section *sec;

	for (sec = PROGRAM(sections)[PROGRAM(version)]; sec; sec = sec->next) {
		if (sec->index == index) {
			return sec;
		}
	}

	return NULL;
}


section *find_section_by_name(unsigned char *name, int version) {
	section *sec;

	for (sec = PROGRAM(sections)[version]; sec; sec = sec->next) {
		if (str_equal(sec->name, name)) {
			return sec;
		}
	}

	return NULL;
}


section *section_clone(section *sec, char *suffix) {
	section *clone;
	char *name;

	size_t length;

	if (sec == NULL) {
		return NULL;
	}

	// Allocates memory for the new descriptor
	clone = (section *) calloc(sizeof(section), 1);

	// Copies the original descriptor to the new one
	memcpy(clone, sec, sizeof(section));

	// Reset some fields
	clone->index = section_id(0, false);
	clone->next = NULL;

	// Compose the section name
	length = strlen((const char *)sec->name) + strlen(suffix) + 2; // one is \0, one is '_'
	name = malloc(sizeof(char) * length);
	bzero(name, length);
	strcpy(name, (const char *)sec->name);
	strcat(name, ".");
	strcat(name, suffix);

	clone->name = (unsigned char *)name;

	// Create a new symbol
	clone->sym = symbol_create(name, SYMBOL_SECTION, SYMBOL_LOCAL, clone, sec->sym->size);

	return clone;
}
