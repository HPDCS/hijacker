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

#include <stdlib.h>

#include <hijacker.h>
#include <prints.h>


/************************************************************
*   Miscellanea
************************************************************/

// #define Q(x) #x
// #define QUOTE(x) Q(x)


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
})


/**
 * Re-allocates previously-allocated dynamic memory and checks that
 * the re-allocations succeeds.
 */
#define hrealloc(data, size) {\
	data = realloc(data, size);\
	if (data == NULL) {\
		herror(true, "Out of memory");\
	}\
}


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
