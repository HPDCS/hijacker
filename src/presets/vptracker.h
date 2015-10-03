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
* @brief Data structures and function prototypes for the virtual page tracker preset
* @author Simone Economo
*/

#pragma once
#ifndef _VPTRACKER_H
#define _VPTRACKER_H

typedef struct {
  // Block-level features
  unsigned int cycles;    // Number of program cycles to which this block participates
  float readratio;        // Number of read operations over block length
  bool hasvector;         // True if it has vector operations
  float score;            // Final instrumentation score

  // Program cycle detection algorithm
  block *lheader;         // Closest loop header
} block_vptracker_data;

extern void vp_init();

extern void vp_track(float threshold, unsigned char *func);

#endif /* _VPTRACKER_H */
