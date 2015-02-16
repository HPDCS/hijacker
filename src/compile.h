#pragma once
#ifndef _COMPILE_H
#define _COMPILE_H


#include <prints.h>



#ifndef COMPILER
/// What shhall we launch for compiling code?
#define COMPILER "gcc"
#endif

#ifndef LINKER
#define LINKER "ld"
#endif


// We must surround the compiler's name with quotes!
#define Q(x) #x
#define QUOTE(x) Q(x)


// Determine which support we have for launching a program
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

	//~ if(execlp(QUOTE(COMPILER), QUOTE(COMPILER), what, __VA_ARGS__, (char *)NULL) == -1) {\
			

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


//compile(prova)

#endif /* _COMPILE_H */

