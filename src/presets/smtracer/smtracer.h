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
* @file vptracker.h
* @brief Data structures and function prototypes for the selective memory tracer preset
* @author Simone Economo
*/

#pragma once
#ifndef _SMTRACER_H
#define _SMTRACER_H

#include <presets.h>

// Name of this preset
#define PRESET_SMTRACER "smtracer"

// Number of general-purpose registers on x86-64
#define SMT_X86_VTABLE_SIZE 16
// Code number of the stack pointer register on x86-(64)
#define SMT_X86_RBP         5


// Selective memory tracer data for a single memory instruction
typedef struct smt_access {
	size_t index;                      // Index in the TLS buffer
	size_t count;                      // Block-wise memory access count
	size_t nequiv;                     // Number of equivalent accesses
	double score;                      // Access instrumentation score

	insn_info *insn;                   // Instruction performing the access
	char vtable[SMT_X86_VTABLE_SIZE];  // Version table for general-purpose registers

	struct smt_access *original;       // Pointer to the original access

	bool instrumented;                 // True if the access was already picked in
	                                   // a previous iteration of the engine
	bool selected;                     // True if the access would be selected by the
	                                   // engine in a non-simulated run
	bool frozen;                       // True if the access is temporarily frozen
	                                   // and is therefore ignored by the engine

	struct smt_access *next;
} smt_access;


// Selective memory tracer data for a single basic block
typedef struct {
	bool selected;              // True if the block is selected by the engine
	double score;               // Relative score ranging in [0,1]
	double memratio;            // Memory sensitivity
	unsigned int cycledepth;    // Total number of joined program cycles

	block *lheader;             // Closest loop header
	smt_access *uniques;        // Candidates list

	double abserror;            // Absolute instrumentation error
	double variety;             // Block variety
	size_t nchosen;             // Total number of chosen uniques
	size_t nirrsim;             // Total number of similar IRR uniques
	size_t nrrisim;             // Total number of similar RRI uniques
	size_t nunique;             // Total number of unique memory instructions
	size_t nirrtot;             // Total number of unique IRR memory instructions
	size_t nrritot;             // Total number of unique RRI memory instructions
	size_t nmtotal;             // Total number of memory instructions
	size_t nitotal;             // Total number of instructions
} smt_data;


extern void smt_init(void);

extern size_t smt_run(char *name, param **params, size_t numparams);

#endif /* _SMTRACER_H */
