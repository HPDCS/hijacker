#pragma once
#ifndef _INTRUMENTOR_RULES_H
#define _INTRUMENTOR_RULES_H

#include <libxml/xmlmemory.h>
#include <libxml/parser.h>

#include <stdbool.h>


#ifdef DEBUG
#define DEBUG_XML_PARSER
#endif



#define MAX_CHILDREN	256



#define CHECK_SET_FLAG(f) do {\
				if(strcmp(token, I_##f##_S) == 0)\
					flags |= I_##f;\
			  } while(0)






typedef struct Call {
	xmlChar	*function;
	xmlChar	*arguments;
	xmlChar	*convention;
} Call;



typedef struct Instruction {
	unsigned int	flags;
	Call		*call;
	xmlChar		*before;
	xmlChar		*after;
	xmlChar		*replace;
} Instruction;



typedef struct Function {
	xmlChar		*name;
	bool		reverseDebugSupport;
	xmlChar		*preamble;
	xmlChar		*postamble;
	Call		*call;
	int		nInstructions;
	Instruction	*instructions[MAX_CHILDREN];
} Function;

typedef struct Executable {
	xmlChar		*entryPoint;
	int		nInject;
	xmlChar		*injectFiles[MAX_CHILDREN];
	bool		reverseDebugSupport;
	int		nInstructions;
	Instruction	*instructions[MAX_CHILDREN];
	int		nFunctions;
	Function	*functions[MAX_CHILDREN];
} Executable;


Executable *parseRuleFile(char *f);

#endif /* _INTRUMENTOR_RULES_H */

