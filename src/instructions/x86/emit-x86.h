/*
 * emit-x86.h
 *
 *  Created on: 23/mag/2014
 *      Author: davide
 */

#ifndef EMIT_X86_H_
#define EMIT_X86_H_


#include <executable.h>
#include "x86.h"

/**
 * Writes the code of the passed function.
 * It writes the code of the function in the x86 form:
 *
 * prefix|opdoce|modR/M|SIB|Displ|Imm
 *
 * The result is put in the buffer, that must be preallocated
 *
 * @param func Function descriptor
 * @param text Text section descriptor to which to write the function body
 * @param reloc Relocation section descriptor to which records possible reference found
 *
 * @return Total bytes written
 *
 */
long write_x86_code(function *func, section *text, section *reloc);


#endif /* EMIT_X86_H_ */
