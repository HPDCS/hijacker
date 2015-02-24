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
* @file options.h
* @brief Command-line options definitions
* @author Alessandro Pellegrini
*/

#pragma once
#ifndef _OPTIONS_H
#define _OPTIONS_H

#include <getopt.h>


static struct option long_options[] = {
	{"config",	required_argument,	0, 'c'},
	{"path",	required_argument,	0, 'p'},
	{"verbose",	optional_argument,	0, 'v'},
	{"input",	required_argument,	0, 'i'},
	{"output",	required_argument,	0, 'o'},
	{0,		0,			0, 0}
};


#endif /* _OPTIONS_H */
