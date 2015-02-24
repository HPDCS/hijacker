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
* @file trampoline.h
* @brief Module to determine at runtime the memory destination address and
* 	 call a specified function
* @author Alessandro Pellegrini
* @author Roberto Vitali
*/

#pragma once
#ifndef _MONITOR64_H
#define _MONITOR64_H

/* Flag inseriti dal parser nella tabella */
#define MOVS		0x01
#define BASE		0x02
#define	IDX		0x04

/* Test sui flag */
#define is_movs(f) 		((f) & MOVS)
#define has_base(f)		((f) & BASE)
#define has_idx(f)		((f) & IDX)


typedef struct {
	unsigned int size;		// Dimensione in byte della scrittura
	char flags;			// I flag riguardanti l'indirizzamento di quest'istruzione
	char base;			// Il valore della base (0x00 - 0x0f)
	char idx;			// Il valore dell'idx (0x00 - 0x0f)
	char scala;			// Scala dell'indice (0, 1, 2 o 4)
	long long offset;		// Il displacement dell'istruzione
	long long pointer;		// The pointer to the function that has to be called
} insn_entry;

#endif

