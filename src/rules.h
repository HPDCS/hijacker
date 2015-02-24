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
* @file rules.h
* @brief Definition of rules and attributes translation units
* @author Alessandro Pellegrini
* @author Davide Cingolani
*/

#pragma once
#ifndef _INTRUMENTOR_RULES_H
#define _INTRUMENTOR_RULES_H

#include <libxml/xmlmemory.h>
#include <libxml/parser.h>

#include <stdbool.h>


#ifdef DEBUG
#define DEBUG_XML_PARSER
#endif


#define ATTRIB_TRUE		"true"
#define ATTRIB_FALSE		"false"
#define ATTRIB_WHERE_BEFORE	"before"
#define ATTRIB_WHERE_AFTER	"after"
#define ASM_ACTION_INS		"insert"
#define ASM_ACTION_SUB		"substitute"

#define MAX_CHILDREN	256

#define CHECK_SET_FLAG(f) do {\
				if(strcmp(token, I_##f##_S) == 0)\
					flags |= I_##f;\
			  } while(0)


typedef struct Call {
	xmlChar	*where;
	xmlChar	*function;
	xmlChar	*arguments;
	xmlChar	*convention;
} Call;


typedef struct Assembly {
	xmlChar	*where;
	xmlChar	*instruction;
	xmlChar	*syntax;
	xmlChar	*arch;
	xmlChar	*action;
} Assembly;


typedef struct Instruction {
	unsigned int	flags;
	Call		*call;
	int		nAssembly;
	Assembly	*assembly[MAX_CHILDREN];
	xmlChar		*before;
	xmlChar		*after;
	xmlChar		*replace;
} Instruction;


typedef struct Function {
	xmlChar		*name;
	Call		*call;
	int		nInstructions;
	Instruction	*instructions[MAX_CHILDREN];
	int		nAssembly;
	Assembly	*assembly[MAX_CHILDREN];
} Function;


typedef struct Executable {
	xmlChar		*entryPoint;
	xmlChar		*suffix;
	int		nInjects;
	xmlChar		*injectFiles[MAX_CHILDREN];
	int		nInstructions;
	Instruction	*instructions[MAX_CHILDREN];
	int		nFunctions;
	Function	*functions[MAX_CHILDREN];
} Executable;


int parseRuleFile(char *f, Executable ***rules);

#endif /* _INTRUMENTOR_RULES_H */

