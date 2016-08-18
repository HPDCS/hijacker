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
#define SMT_VTABLE_SIZE 16


typedef struct smt_access {
  size_t count;                   // Access count
  size_t index;                   // Index in the TLS buffer

  insn_info *insn;                // Instruction performing the access

  bool instrumented;              // True if the access was already logged
  bool selected;                  // True if the access is selected by the engine

  struct smt_access *original;    // Pointer to the equal original access

  char vtable[SMT_VTABLE_SIZE];   // Version table for general-purpose registers
  double score;                   // Access instrumentation score

  struct smt_access *next;
} smt_access;


typedef struct {
  // Block-level features
  block *lheader;             // Closest loop header
  unsigned int cycles;        // Number of joined program cycles
  double memratio;            // Memory sensitivity

  double score;               // Relative score ranging in [0,1]

  smt_access *candidates;     // Candidates list

  size_t ncandidates;         // Total number of candidate memory instructions
  size_t nirr;                // Number of candidate IRR memory instructions
  size_t nrri;                // Number of candidate RRI memory instructions
  size_t ntotal;              // Total number of memory instructions
} smt_data;


extern void smt_init(void);

extern size_t smt_run(char *name, param **params, size_t numparams);

#endif /* _SMTRACER_H */
