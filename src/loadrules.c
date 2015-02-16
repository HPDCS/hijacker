#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <libxml/xmlmemory.h>
#include <libxml/parser.h>

#include <hijacker.h>
#include <rules.h>
#include <instruction.h>
#include <prints.h>

/// Generate spacing for 
#define SPACES(level) 	{int i;\
			for(i = 0; i < level; i++) {\
					hnotice(3, "---");\
			}\
			}


static void traverseCall(Call *c, int level) {
	SPACES(level); hnotice(3, "Call:\n");
	SPACES(level + 1); hnotice(3, "Function: '%s'\n", c->function);
	SPACES(level + 1); hnotice(3, "Arguments: '%s'\n", c->arguments);
	SPACES(level + 1); hnotice(3, "Convention: '%s'\n", c->convention);
}


static void traverseInstruction(Instruction *i, int level) {
	SPACES(level); hnotice(3, "Instruction: %#08x\n", i->flags);
	SPACES(level + 1); hnotice(3, "before: '%s'\n", i->before);
	SPACES(level + 1); hnotice(3, "after: '%s'\n", i->after);
	SPACES(level + 1); hnotice(3, "replace: '%s'\n", i->replace);
	if(i->call != NULL)
		traverseCall(i->call, level + 1);
}

static void traverseFunction(Function *f, int level) {
	int i;

	SPACES(level); hnotice(3, "Function: '%s'\n", f->name);
//	SPACES(level + 1); hnotice(3, "preamble: '%s'\n", f->preamble);
//	SPACES(level + 1); hnotice(3, "postamble: '%s'\n", f->postamble);
	traverseCall(f->call, level + 1);
	for(i = 0; i < f->nInstructions; i++) {
		traverseInstruction(f->instructions[i], level + 1);
	}
}

static void traverseTree(Executable *e) {
	int i;

	hnotice(3, "--Entry Point: '%s'\n", e->entryPoint);
	
	for(i = 0; i < e->nInjects; i++) {
		hnotice(3, "--Inject File: '%s'\n", e->injectFiles[i]);
	}

	for(i = 0; i < e->nInstructions; i++) {
		traverseInstruction(e->instructions[i], 1);
	}

	for(i = 0; i < e->nFunctions; i++) {
		traverseFunction(e->functions[i], 1);
	}
}







/* Actual parsing */



static inline bool parseTrueFalse(xmlChar *xmlStr) {

	char *str = (char *)xmlStr;

	if(strcmp(str, "true") == 0) {
		return true;
	} else if (strcmp(str, "false") == 0) {
		return false;
	} else {
		herror(false, "Unrecognized option: '%s'. Defaulting to 'false'\n", str);
	}

	return false;
}



static Call *parseCall(/*xmlDocPtr doc, xmlNsPtr ns, */xmlNodePtr cur) {
	Call *ret = NULL;

	// Allocate the struct
	ret = (Call *) malloc(sizeof(Call));
	if (ret == NULL) {
		herror(true, "Out of memory\n");
	}
	memset(ret, 0, sizeof(Call));

	// Get the attributes
	if (cur != NULL) {
		ret->where = xmlGetProp(cur, (const xmlChar *)"where");
		ret->function = xmlGetProp(cur, (const xmlChar *)"function");
		ret->arguments = xmlGetProp(cur, (const xmlChar *)"arguments");
		ret->convention = xmlGetProp(cur, (const xmlChar *)"convention");
	}

	return ret;

}


static Assembly *parseAssembly(xmlNodePtr cur) {
	Assembly *ret = NULL;

	// Allocate the struct
	ret = (Assembly *) malloc(sizeof(Assembly));
	if (ret == NULL) {
		herror(true, "Out of memory\n");
	}
	memset(ret, 0, sizeof(Assembly));

	// Get the attributes
	if(cur != NULL) {
		ret->where = xmlGetProp(cur, (const xmlChar *)"where");
		ret->instruction = xmlGetProp(cur, (const xmlChar *)"instruction");
		ret->syntax = xmlGetProp(cur, (const xmlChar *)"syntax");
		ret->arch = xmlGetProp(cur, (const xmlChar *)"arch");
		ret->action = xmlGetProp(cur, (const xmlChar *)"action");
	}

	return ret;
}



static xmlChar *parseInject(/*xmlDocPtr doc, xmlNsPtr ns, */xmlNodePtr cur) {
	xmlChar *curFile = NULL;

	// Get the file's name string
	if (cur != NULL) {
		
		curFile = xmlGetProp(cur, (const xmlChar *)"file");
	}

	return curFile;
}



static unsigned int parseInstructionFlags(xmlChar *str) {
	char *source;
	char *curSource;
	char *token;
	int flags = 0;

	// Make a temporary copy
	source = (char *)malloc(strlen((char *)str) + 1);
	strcpy(source, (char *)str);

	// Tokenize the string
	curSource = source;
	

	while((token = strtok(curSource, "| ")) != NULL) { // space is there to make the parser ignore them

		curSource = NULL; // this will make strtok continue parsing the same line

		// Set flags accordingly.
		CHECK_SET_FLAG(MEMRD);
		CHECK_SET_FLAG(MEMWR);
		CHECK_SET_FLAG(CTRL);
		CHECK_SET_FLAG(JUMP);
		CHECK_SET_FLAG(CALL);
		CHECK_SET_FLAG(RET);
		CHECK_SET_FLAG(CONDITIONAL);
		CHECK_SET_FLAG(STRING);
		CHECK_SET_FLAG(ALU);
		CHECK_SET_FLAG(FPU);
		CHECK_SET_FLAG(MMX);
		CHECK_SET_FLAG(XMM);
		CHECK_SET_FLAG(SSE);
		CHECK_SET_FLAG(SSE2);
		CHECK_SET_FLAG(PUSHPOP);
		CHECK_SET_FLAG(STACK);
		CHECK_SET_FLAG(JUMPIND);
	}
	

	// Free the copy
	free(source);

	return flags;
}



static Instruction *parseInstruction(/*xmlDocPtr doc, */xmlNsPtr ns, xmlNodePtr cur) {
	Instruction *ret = NULL;
	Call *curCall;
	Assembly *curAssembly;

	// Allocate the struct
	ret = (Instruction *) malloc(sizeof(Instruction));
	if (ret == NULL) {
		herror(true, "Out of memory\n");
	}
	memset(ret, 0, sizeof(Instruction));

	// Get the instruction's attributes
	if (cur != NULL) {
		ret->flags = parseInstructionFlags(xmlGetProp(cur, (const xmlChar *)"type"));
		ret->before = xmlGetProp(cur, (const xmlChar *)"injectBefore");
		ret->after = xmlGetProp(cur, (const xmlChar *)"injectAfter");
		ret->replace = xmlGetProp(cur, (const xmlChar *)"replace");
	}

	// Don't care what the top level element's name is
	// and scan the remainder of the xml tree
	cur = cur->xmlChildrenNode;
	while (cur != NULL) {

		// Call
		if (xmlStrcmp(cur->name, (const xmlChar *)"AddCall") == 0 && cur->ns == ns) {
			curCall = parseCall(/*doc, ns, */cur);
			if (curCall != NULL && ret->call == NULL) {
				ret->call = curCall;
			}
		}

		// Assembly
		else if (xmlStrcmp(cur->name, (const xmlChar *)"Assembly") == 0 && cur->ns == ns) {
			curAssembly = parseAssembly(cur);
			if (curAssembly != NULL) {
				ret->assembly[ret->nAssembly++] = curAssembly;
			}
		}

		cur = cur->next;
	}

	return ret;
}



static Function *parseFunction(/*xmlDocPtr doc, */xmlNsPtr ns, xmlNodePtr cur) {
	Function *ret = NULL;
	Call *curCall;
	Instruction *curInstruction;
	Assembly *curAssembly;

	// Allocate the struct
	ret = (Function *) malloc(sizeof(Function));
	if (ret == NULL) {
		herror(true, "Out of memory\n");
	}
	memset(ret, 0, sizeof(Function));

	// Get the function's attributes
	if (cur != NULL) {
		ret->name = xmlGetProp(cur, (const xmlChar *)"name");
//		ret->preamble = xmlGetProp(cur, (const xmlChar *)"preamble");
//		ret->postamble = xmlGetProp(cur, (const xmlChar *)"postamble");
	}


	// Don't care what the top level element's name is
	// and scan the remainder of the xml tree
	cur = cur->xmlChildrenNode;
	while (cur != NULL) {

		// Call
		if (xmlStrcmp(cur->name, (const xmlChar *)"AddCall") == 0 && cur->ns == ns) {
			curCall = parseCall(/*doc, ns, */cur);
			if (curCall != NULL && ret->call == NULL) {
				ret->call = curCall;
			}
		}

		// Instruction
		else if (xmlStrcmp(cur->name, (const xmlChar *)"Instruction") == 0 && cur->ns == ns) {
			curInstruction = parseInstruction(/*doc, */ns, cur);
			if (curInstruction != NULL && ret->nInstructions < MAX_CHILDREN) {
				ret->instructions[ret->nInstructions++] = curInstruction;
			}
		}

		// Assembly
		else if (xmlStrcmp(cur->name, (const xmlChar *)"Assembly") == 0 && cur->ns == ns) {
			curAssembly = parseAssembly(cur);
			if (curAssembly != NULL && ret->nAssembly < MAX_CHILDREN) {
				ret->assembly[ret->nAssembly++] = curAssembly;
			}
		}

		cur = cur->next;
	}

	return ret;
}



static int parseExecutable(char *filename, Executable ***rules) {
	
	int nExecutables = 0;

	xmlDocPtr doc;
	xmlNsPtr ns;
	xmlNodePtr cur;
	xmlNodePtr execNode;

	xmlChar *curInject;
	Instruction *curInstruction;
	Function *curFunction;
	Executable *exec;
	Executable **execPtr;

#ifdef LIBXML_SAX1_ENABLED
	// build an XML tree from the file
	doc = xmlParseFile(filename);
	if (doc == NULL)
		return -1;
#else
	// Library compiled without needed interfaces, unable to parse...
	herror(true, "XML SAX Library is compiled without required supports. Please reinstall the library.\n");
#endif	/* LIBXML_SAX1_ENABLED */


	// Check if the document is of the right kind
	cur = xmlDocGetRootElement(doc);
	if (cur == NULL) {
		xmlFreeDoc(doc);
		herror(true, "Empty rule file\n");
	}

	ns = xmlSearchNsByHref(doc, cur, (const xmlChar *) "http://www.dis.uniroma1.it/~hpdcs/");
	if (ns == NULL) {
		xmlFreeDoc(doc);
		herror(true, "Document of the wrong type, hijacker Namespace not found\n");
	}

	if (xmlStrcmp(cur->name, (const xmlChar *)"Rules")) {
		xmlFreeDoc(doc);
		herror(true, "Document of the wrong type, root node != Rules\n");
	}

	// Allocate the structure to be returned
	execPtr = (Executable **) malloc(sizeof(Executable *) * MAX_CHILDREN);
	if (execPtr == NULL) {
		xmlFreeDoc(doc);
		herror(true, "Out of memory\n");
	}
	memset(execPtr, 0, sizeof(Executable *) * MAX_CHILDREN);
	*rules = execPtr;

	/*
	 * Now, walk the tree.
	 */
	// First level we expect just Executables
	execNode = cur->xmlChildrenNode;
	while(execNode) {
			
		while (execNode && xmlIsBlankNode(cur)) {
			execNode = execNode->next;
		}
		if (execNode == 0) {
			xmlFreeDoc(doc);
			break;
		}

		if ((xmlStrcmp(execNode->name, (const xmlChar *)"Executable") != 0) || (execNode->ns != ns)) {
			execNode = execNode->next;
			continue;
		}

		// Get memory for the current set of instrumentation rules
		(*rules)[nExecutables++] = exec = (Executable *) malloc(sizeof(Executable));
		bzero(exec, sizeof(Executable));

		// Get and store the executable's attributes, if any
		exec->entryPoint = xmlGetProp(execNode, (const xmlChar *)"entryPoint");


		// Parse second level and call other parsers depending on the node type
		cur = execNode->xmlChildrenNode;
		while (cur != NULL) {

			// Inject Node
			if (xmlStrcmp(cur->name, (const xmlChar *)"Inject") == 0 && cur->ns == ns) {
				curInject = parseInject(/*doc, ns, */cur);
				if (curInject != NULL && exec->nInjects < MAX_CHILDREN) {
					exec->injectFiles[exec->nInjects++] = curInject;
				}
			}

			// Instruction Node
			else if (xmlStrcmp(cur->name, (const xmlChar *)"Instruction") == 0 && cur->ns == ns) {
				curInstruction = parseInstruction(/*doc, */ns, cur);
				if (curInstruction != NULL && exec->nInstructions < MAX_CHILDREN) {
					exec->instructions[exec->nInstructions++] = curInstruction;
				}
			}

			// Function Node
			else if (xmlStrcmp(cur->name, (const xmlChar *)"Function") == 0 && cur->ns == ns) {
				curFunction = parseFunction(/*doc, */ns, cur);
				if (curFunction != NULL && exec->nFunctions < MAX_CHILDREN) {
					exec->functions[exec->nFunctions++] = curFunction;
				}
			}

			cur = cur->next;
		}
		
		execNode = execNode->next;
	}

	// Once the parsing is finished the document is disposed
	xmlFreeDoc(doc);

	// Check if some executable node has been met
	if (!nExecutables) {
		herror(false, "Document of the wrong type, was '%s', Executable expected\n", execNode->name);
	//	xmlFreeDoc(doc);
		return -1;
	}
	
	// nExecutables is used as offset so far
	return nExecutables;
}



int parseRuleFile(char *f, Executable ***rules) {
	int size;
	register unsigned int i;
	
	// Early check on file existence to avoid ugly error messages
	if(!file_exists(f)) {
		return -1;
	}

	// Do not generate nodes for formatting spaces
	LIBXML_TEST_VERSION xmlKeepBlanksDefault(0);

	// Parse the requested file
	size = parseExecutable(f, rules);
	if(size == -1) {
		hfail();
		herror(true, "Unable to parse configuration file '%s'\n", config.rules_file);
	}

	// Clean up everything
	xmlCleanupParser();

	if(config.verbose > 10) {
		hnotice(3, "Found %d executable versions\n", size);
		for(i = 0; i < size; i++) {
			hnotice(3, "Executable version %d:\n", i+1);
			traverseTree((*rules)[i]);
		}
	}

	return size;
}


