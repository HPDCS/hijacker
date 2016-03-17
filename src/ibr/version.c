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
* @file version.c
* @brief Module to handle versions in the IBR
* @author Simone Economo
*/


ver_t *version_create(const char *name) {
	ver_t *version;

	if (name == NULL) {
		hinternal();
	}

	// Make room for a new function descriptor
	version = hcalloc(sizeof(ver_t));

	// Fill version descriptor fields
	version->number = PROGRAM(nversion);
	version->name = name;

	// Insert the descriptor into the version array
	PROGRAM(versions)[version->number] = version;
	PROGRAM(nversion) += 1;

	if (version->number != 0) {
		// TODO: Clone *everything* !
	}

	return version;
}


ver_t *version_switch(unsigned long number) {
	ver_t *version;

	if (number >= MAX_VERSIONS) {
		hinternal();
	}

	// Can be NULL if there's no version with that number
	version = PROGRAM(versions)[number];

	if (version != NULL) {
		PROGRAM(cversion) = version;
	}

	return version;
}
