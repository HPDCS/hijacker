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
* @brief Implementation module to register presets
* @author Simone Economo
*/

#include <string.h>

#include <prints.h>
#include <hijacker.h>
#include <presets.h>

void preset_register(char *name, preset_init_func init_func, preset_apply_func apply_func) {
  preset *current;

  if (name == NULL || init_func == NULL || apply_func == NULL) {
    hinternal();
  }

  current = calloc(sizeof(preset), 1);
  current->name = name;
  current->init_func = init_func;
  current->apply_func = apply_func;
  current->next = config.presets;

  hnotice(2, "Registered preset '%s'\n", current->name);

  config.presets = current;
}

preset *preset_find(char *name) {
  preset *current;

  if (name == NULL) {
    hinternal();
  }

  current = config.presets;

  while (current) {
    if (!strcmp((unsigned char *) current->name, name)) {
      return current;
    }

    current = current->next;
  }

  return NULL;
}
