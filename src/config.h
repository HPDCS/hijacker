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
* @file config.h
* @brief Main configuration symbols
* @author Alessandro Pellegrini
*/

#pragma once
#ifndef _CONFIG_H
#define _CONFIG_H

#include <ibr.h>

#include <presets/presets.h>
#include <rules/load-rules.h>
#include <executables/executable.h>


typedef struct configuration {
	unsigned int verbose;
	const char *rules_file;
	const char *input_file;
	const char *output_file;
	const char *inject_path;

	obj_t program;
	preset *presets;

	Executable **versions;
	unsigned int nVersions;
} configuration;

extern configuration config;

/// Easy access to program flags
#define PROGRAM(field) (config.program.field)

/// Easy access to symbols and code
// #define SYMBOLS PROGRAM(v_symbols)[PROGRAM(version)]
// #define CODE PROGRAM(v_code)[PROGRAM(version)]

/// Default output name
#define DEFAULT_OUT_NAME  "hijacked.o"

#endif /* _HIJACKER_H */
