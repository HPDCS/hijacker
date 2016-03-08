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
* @file hijacker.h
* @brief Main types and qualifiers
* @author Simone Economo
*/

#pragma once
#ifndef _HIJACKER_H
#define _HIJACKER_H


// Enhanced C data types are included pro-actively
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>


/************************************************************
*   Function qualifiers
************************************************************/

/// A function which is inlined only when optimizations
/// are requested prior to compilation.
/// Rule of thumb: use a weak_inline function when you want
/// a regular C inline function.
#define weak_inline inline


/// A function which is always inlined regardless of the
/// presence of compiling optimization flags.
/// Rule of thumb: use a strong_inline function when you
/// are tempted to use a parametrized macro.
#define strong_inline inline __attribute__((always_inline))


/************************************************************
*   Primitive data types
************************************************************/

/// Everything which represents a positive displacement
/// from the beginning of a parent container
typedef size_t addr_t;


/// Either a positive or a negative displacement from
/// the current position
typedef ptrdiff_t off_t;


#endif /* _HIJACKER_H */

