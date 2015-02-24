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
* @file compile.h
* @brief Compile and Link macros
* @author Alessandro Pellegrini
*/

#pragma once
#ifndef _COMPILE_H
#define _COMPILE_H

#include <prints.h>


// TODO: move to autotools
#ifndef COMPILER
/// What shall we launch for compiling code?
#define COMPILER "gcc"
#endif

#ifndef LINKER
#define LINKER "ld"
#endif


/// We must surround the compiler's name with quotes!
#define Q(x) #x
#define QUOTE(x) Q(x)


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

  /// Compile source with several parameters
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

#endif /* _COMPILE_H */
