#pragma once
#ifndef _HIJACKER_H
#define _HIJACKER_H

#include <stdbool.h>
#include <rules.h>
#include <executables/executable.h>

typedef struct _configuration {
	int		verbose;
	char		*rules_file;
	Executable	*rules;
	char	  	*input;
	char		*output;
	char		*inject_path;
	executable_info	program;
} configuration;


/// Easily access program flags
#define PROGRAM(field) (config.program.field)


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

