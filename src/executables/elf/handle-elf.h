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
* @file handle-elf.c
* @brief Functions to manipulate already-parsed ELF object files
* @author Davide Cingolani
*/

#pragma once
#ifndef _HANDLE_ELF_H
#define _HANDLE_ELF_H

#include <executable.h>
#include <instruction.h>




/**
 * Switches to the given executable version. If the version passed is grater than the
 * max version available, than a new executable version to instrument is created from scratch.
 * Note that max 256 versions are currently supported.
 *
 * @param version The integer representing the version to switch
 *
 * @return An integer representing the current instrumenting version.
 */
int switch_executable_version (int version);

#endif /* _HANDLE_ELF_H */
