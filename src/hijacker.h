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
* @file hijacker.h
* @brief Main symbols
* @author Alessandro Pellegrini
*/

#pragma once
#ifndef _HIJACKER_H
#define _HIJACKER_H

#include <stdbool.h>

#include <rules/load-rules.h>
#include <executables/executable.h>

typedef struct _configuration {
	int		verbose;
	char		*rules_file;
	Executable	**rules;
	int		nExecutables;
	char	  	*input;
	char		*output;
	char		*inject_path;
	executable_info	program;
} configuration;


/// Easily access program flags
#define PROGRAM(field) (config.program.field)

#define SYMBOLS PROGRAM(v_symbols)[PROGRAM(version)]
#define CODE PROGRAM(v_code)[PROGRAM(version)]


/// Default output name
#define DEFAULT_OUT_NAME	"hijacked.o"


// This is an OS-dependent way to check if a file exists
#if defined(WIN32) || defined(WIN64)
  #include <windows.h>
  #define file_exists(f) (GetFileAttributes((f)) != INVALID_FILE_ATTRIBUTES)
#elif defined(__unix)
  #include <unistd.h>
  #define file_exists(f) (access((f), F_OK) != -1)
#else
  // This is not exactly safe, but we are not given anything better...
  #include <stdio.h>
  #define file_exists(f) ({\
			   FILE * file = fopen((f),"r+");\
			   fclose(file);\
			   file != NULL;\
			 })
#endif

extern configuration config;

#endif /* _HIJACKER_H */

