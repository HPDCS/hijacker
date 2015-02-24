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
* @file emit-x86.c
* @brief Support functions to generate (needed) x86 assembly instructions on the fly
* @author Davide Cingolani
* @date May 23, 2014
*/

#pragma once
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
