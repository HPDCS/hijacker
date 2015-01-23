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

