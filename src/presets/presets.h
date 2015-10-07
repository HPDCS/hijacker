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
* @file presets.h
* @brief Prototypes and data structures to register presets
* @author Simone Economo
*/

#pragma once
#ifndef _PRESETS_H
#define _PRESETS_H

#include <executable.h>

typedef struct preset preset;
typedef struct param param;

typedef void (*preset_init_func)(void);
typedef size_t (*preset_apply_func)(char *func, param **params, size_t numparams);

struct preset {
  char *name;
  bool initialized[MAX_VERSIONS];

  preset_init_func init_func;
  preset_apply_func apply_func;

  struct preset *next;
};

struct param {
  char *name;
  char *value;
};

extern void preset_register(char *name, preset_init_func init_func, preset_apply_func apply_func);
extern preset *preset_find(char *name);

#endif /* _PRESETS_H */
