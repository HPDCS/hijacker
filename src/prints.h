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
* @file prints.h
* @brief Fancy output generation macros
* @author Alessandro Pellegrini
*/

#pragma once
#ifndef _PRINTS_H
#define _PRINTS_H

#include <stdio.h>
#include <stdlib.h>

#include <hijacker.h>


/* FANCY GRAPHICS! */

#define RESET		 0
#define BOLD		 1
#define NORMAL_INTENSITY 22
#define UNDERLINE	 4
#define NO_UNDERLINE	 24
#define BLINK		 6
#define HIDDEN		 8

#define BLACK_F		 30
#define RED_F		 31
#define GREEN_F		 32
#define YELLOW_F	 33
#define BLUE_F		 34
#define MAGENTA_F	 35
#define CYAN_F		 36
#define WHITE_F		 37

#define BLACK_B		 40
#define RED_B		 41
#define GREEN_B		 42
#define YELLOW_B	 43
#define BLUE_B		 44
#define MAGENTA_B	 45
#define CYAN_B		 46
#define WHITE_B		 47

#define BRIGHT_BLACK_F	 90
#define BRIGHT_RED_F	 91
#define BRIGHT_GREEN_F	 92
#define BRIGHT_YELLOW_F	 93
#define BRIGHT_BLUE_F	 94
#define BRIGHT_MAGENTA_F 95
#define BRIGHT_CYAN_F	 96
#define BRIGHT_WHITE_F	 97

#define BRIGHT_BLACK_B	 100
#define BRIGHT_RED_B	 101
#define BRIGHT_GREEN_B	 102
#define BRIGHT_YELLOW_B	 103
#define BRIGHT_BLUE_B	 104
#define BRIGHT_MAGENTA_B 105
#define BRIGHT_CYAN_B	 106
#define BRIGHT_WHITE_B	 107

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
		printf("\e[1000C");\
		printf("\e[%dD", chars);\
	} while(0)


/* PRINTING MACROS TO BE USED IN THE CODE */


#define herror(fatal, ...) do {\
		fprintf(stderr, "[");\
		fprintf(stderr, (fatal ? "\e[1;31mFATAL ERROR\e[0m" : "\e[1;33mWARNING\e[0m")); \
		set_style(RESET);\
		fprintf(stderr, "] %s:%d: ", __FILE__, __LINE__);\
		fprintf(stderr, __VA_ARGS__);\
		fflush(stderr);\
		if(fatal) {\
			exit(EXIT_FAILURE);\
		}\
	} while(0)



#define hnotice(verb_level, ...) do {\
		if(config.verbose >= (verb_level)) {\
			printf("%*s", verb_level, " ");\
			yellow_arrow();\
			printf(__VA_ARGS__);\
			fflush(stdout);\
		}\
	} while(0)



#define hprint(...) do {\
		blue_arrow();\
		printf(__VA_ARGS__);\
		fflush(stdout);\
	} while(0)



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

#define	hinternal()	herror(true, "%s: internal error at line %d\n", __FILE__, __LINE__)


#define hhijacker() (printf("HIJACKER\n"))

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


#endif /* _PRINTS_H */
