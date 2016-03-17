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


/// A configuration object for the current hijacking session.
typedef struct configuration {
	unsigned int verbose;     /// Requested verbosity level for debug prints
	const char *rules_file;   /// Path to the configuration file to be parsed
	const char *input_file;   /// Path to the input file to be loaded
	const char *output_file;  /// Path to the output file to be written
	const char *inject_path;  /// Path in which injected files will be found

	obj_t program;            /// Object file which is hijacked
	preset *presets;          /// List of registered presets

	Executable **versions;    /// List of version rules to be applied
	size_t nVersions;         /// Number of version rules
} configuration;


/// Global configuration object
extern configuration config;


/// Easy access to program fields
#define PROGRAM(field) (config.program.field)

/// Easy access to current version fields
#define VERSION(field) (PROGRAM(cversion)->field)

/// Default output name
#define DEFAULT_OUT_NAME "hijacked.o"


#endif /* _CONFIG_H */
