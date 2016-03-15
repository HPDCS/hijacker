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
* @file utils.h
* @brief Utility functions used throughout all the codebase
* @author Alessandro Pellegrini
* @author Davide Cingolani
* @author Simone Economo
*/

#ifndef _UTILS_H_
#define _UTILS_H_

#include <stdbool.h>
#include <stdlib.h>

#include <init.h>
// #include <config.h>


/************************************************************
*   Printing utils
************************************************************/

// FANCY GRAPHICS!

#define RESET            0
#define BOLD             1
#define NORMAL_INTENSITY 22
#define UNDERLINE        4
#define NO_UNDERLINE     24
#define BLINK            6
#define HIDDEN           8

#define BLACK_F          30
#define RED_F            31
#define GREEN_F          32
#define YELLOW_F         33
#define BLUE_F           34
#define MAGENTA_F        35
#define CYAN_F           36
#define WHITE_F          37

#define BLACK_B          40
#define RED_B            41
#define GREEN_B          42
#define YELLOW_B         43
#define BLUE_B           44
#define MAGENTA_B        45
#define CYAN_B           46
#define WHITE_B          47

#define BRIGHT_BLACK_F   90
#define BRIGHT_RED_F     91
#define BRIGHT_GREEN_F   92
#define BRIGHT_YELLOW_F  93
#define BRIGHT_BLUE_F    94
#define BRIGHT_MAGENTA_F 95
#define BRIGHT_CYAN_F    96
#define BRIGHT_WHITE_F   97

#define BRIGHT_BLACK_B   100
#define BRIGHT_RED_B     101
#define BRIGHT_GREEN_B   102
#define BRIGHT_YELLOW_B  103
#define BRIGHT_BLUE_B    104
#define BRIGHT_MAGENTA_B 105
#define BRIGHT_CYAN_B    106
#define BRIGHT_WHITE_B   107

#define set_style(attrib) (printf("\e[%dm", attrib))

#define blue_arrow() do {\
		set_style(BOLD);\
		set_style(CYAN_F);\
		printf("=> ");\
		set_style(RESET);\
	} while(0)

#define yellow_arrow() do {\
		set_style(BOLD);\
		set_style(YELLOW_F);\
		printf("=> ");\
		set_style(RESET);\
	} while(0)

// 1000C is an unnice hack...
#define align_right(chars) do {\
		printf("\e[1000C"); \
		printf("\e[%dD", chars);\
	} while(0)


/// Prints a fatal error or a warning to screen, just
/// depending on the truthfulness of the `fatal` parameter.
#define herror(fatal, ...) do {\
		fprintf(stderr, "[");\
		fprintf(stderr, (fatal ? "\e[1;31mFATAL ERROR\e[0m" : "\e[1;33mWARNING\e[0m")); \
		set_style(RESET);\
		fprintf(stderr, "] %s:%d: ", __FILE__, __LINE__);\
		fprintf(stderr, __VA_ARGS__);\
		if(fatal) {\
			exit(EXIT_FAILURE);\
		}\
	} while(0)


/// Prints a predefined fatal error message to screen,
/// specifying the file and line locations in the code
/// where the error has occurred.
#define hinternal() herror(true, "%s: internal error at line %d\n", __FILE__, __LINE__)


/// Prints a notice to screen, which will be shown only
/// if its verbosity level represented by the `verb_level`
/// parameter is below the configured verbosity threshold.
#define hnotice(verb_level, ...) do {\
		if(config.verbose >= (verb_level)) {\
			printf("%*s", verb_level, " ");\
			yellow_arrow();\
			printf(__VA_ARGS__);\
		}\
	} while(0)


/// Prints a generic message to screen.
#define hprint(...) do {\
		blue_arrow();\
		printf(__VA_ARGS__);\
		fflush(stdout);\
	} while(0)


/// Prints a confirmation message to screen, useful to
/// indicate the positive termination of an arbitrary
/// processing step.
#define hsuccess() do {\
		if(config.verbose > 0) {\
			align_right(9);\
			printf("[");\
			set_style(BOLD);\
			set_style(CYAN_F);\
			printf("SUCCESS");\
			set_style(RESET);\
			printf("]\n");\
		}\
	} while(0)


/// Prints a failure message to screen, useful to indicate
/// the unexpected failure of an arbitrary processing step.
#define hfail() do {\
		if(config.verbose > 0) {\
			align_right(6);\
			printf("[");\
			set_style(BOLD);\
			set_style(RED_F);\
			printf("FAIL");\
			set_style(RESET);\
			printf("]\n");\
		}\
	} while(0)


/// Prints an hexadecimal dump of the buffer located at
/// address `addr` up to `len` bytes.
/// The dump is preceded by a custom message `desc` and
/// a verbosity level represented by `verb_level`.
#define hdump(verb_level, desc, addr, len) do {\
	if(config.verbose >= verb_level){\
		if(!len) {\
			hnotice(verb_level, "Nothing to dump!\n\n");\
			break;\
		}\
		hnotice(verb_level, "%s:\n\n", desc);\
		hexdump(addr, len);\
		printf("\n");\
	}\
} while(0)


/// Prints a welcome message
#define hhijacker() (printf("HIJACKER\n"))


/**
 * Perform an hexadecimal dump of data of a given number of bytes,
 * starting from an initial address in memory.
 */
void hexdump(void *data, size_t len);


/************************************************************
*   String utils
************************************************************/

/**
 * Checks whether two strings have the same sequence of characters.
 *
 * @param str1 Pointer to the base string.
 * @param str2 Pointer to the comparison string.
 *
 * @return True if the two strings are equal.
 */
strong_inline bool strequal(const char *str1, const char *str2) {
	return (strcmp((str1), (str2)) == 0);
}


/**
 * Checks whether a string has another string as prefix.
 *
 * @param str Pointer to the base string.
 * @param pre Pointer to the prefix string.
 *
 * @return True if the first string is prefixed by the second.
 */
strong_inline bool strprefix(const char *str, const char *pre) {
	return (strncmp((pre), (str), strlen((pre))) == 0);
}


/************************************************************
*   Memory allocation utils
************************************************************/

/**
 * Allocates non-initialized dynamic memory and checks that
 * the allocations succeeds.
 */
#define hmalloc(size) ({\
		void *data = malloc(size);\
		if (data == NULL) {\
			herror(true, "Out of memory");\
		}\
		data;\
	})


/**
 * Allocates zero-initialized dynamic memory and checks that
 * the allocations succeeds.
 */
#define hcalloc(size) ({\
		void *data = calloc(size, 1);\
		if (data == NULL) {\
			herror(true, "Out of memory");\
		}\
		data;\
	})


/**
 * Re-allocates previously-allocated dynamic memory and checks that
 * the re-allocations succeeds.
 */
#define hrealloc(data, size) ({\
		data = realloc(data, size);\
		if (data == NULL) {\
			herror(true, "Out of memory");\
		}\
		data;\
	})


// Poison all original dynamic memory allocation functions so that
// they cannot be used directly anymore
#ifdef __GNUC__
#pragma GCC poison malloc calloc realloc
#endif


/************************************************************
*   Filesystem utils
************************************************************/

// OS-specific way to check for file existence
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


/************************************************************
*   Compilation tool-chain utils
************************************************************/

// TODO: move to autotools
#ifndef COMPILER
/// What shall we launch for compiling code?
#define COMPILER "gcc"
#endif

#ifndef LINKER
#define LINKER "ld"
#endif


/// Determine which support we have for launching a program
#if defined(WIN32) || defined(WIN64)
	#include <windows.h>
	#warning Windows was never tested!!!!

	#define compile(what, ...) do {\
			PROCESS_INFORMATION pif;\
			STARTUPINFO si;\
			ZeroMemory(&si, sizeof(si));\
			si.cb = sizeof(si);\
			BOOL bRet = CreateProcess(\
				what, \
				NULL, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pif);\
			CloseHandle(pif.hProcess);\
			CloseHandle(pif.hThread);\
			WaitForSingleObject(pif.hProcess, INFINITE);\
		} while(0)

#elif defined(__unix)
	#include <unistd.h>
	#include <stdlib.h>
	#include <sys/wait.h>
	#include <errno.h>

	#define compile(what, ...) do {\
			int status;\
			if(fork() != 0) {\
				wait(&status);\
			} else {\
				if(execlp("gcc", "gcc", what, __VA_ARGS__, (char *)NULL) == -1) {\
					herror(true, "Unable to launch the compiler '%s' (error %d: '%s')\n", COMPILER, errno, strerror(errno));\
				}\
			}\
			if(status != 0) {\
				herror(true, "Error compiling '%s' (error %d: '%s')\n", what, status, strerror(status));\
			}\
		} while(0)

	#define link(what, ...) do {\
			int status;\
			if(fork() != 0) {\
				wait(&status);\
			} else {\
				if(execlp("ld", "ld", what, __VA_ARGS__, (char *)NULL) == -1) {\
					herror(true, "Unable to launch the linker '%s' (error %d: '%s')\n", LINKER, errno, strerror(errno));\
				}\
			}\
			if(status != 0) {\
				herror(true, "Error linking '%s' (error %d: '%s')\n", what, status, strerror(status));\
			}\
		} while(0)

	#define execute(what, ...) do {\
			int status;\
			if(fork() != 0) {\
				wait(&status);\
			} else {\
				if(execlp(what, what, __VA_ARGS__, (char *)NULL) == -1) {\
					herror(true, "Unable to launch '%s'\n", what);\
					}\
			}\
			if(status != 0) {\
				herror(true, "Error executing '%s' (error %d: '%s')\n", what, status, strerror(status));\
			}\
		} while(0)

#else
	#error Unable to determine a viable support for launching external programs
#endif


#endif /* _UTILS_H_ */
