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
* @file main.c
* @brief Hijacker entry point
* @author Alessandro Pellegrini
* @author Davide Cingolani
*/

#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>
#include <string.h>


#include <hijacker.h>
#include <options.h>
#include <rules.h>
#include <prints.h>
#include <compile.h>
#include <rules/apply-rules.h>


/// Global configuration
configuration config;

/// Information and memory map of the object being processed


static void display_usage(char **argv) {
	printf("%s [OPTIONS]\n\n", argv[0]);
	printf("REQUIRED OPTIONS:\n");
	printf("\t-c <file>, --config <file>: Configuration-rules file\n");
	printf("\t-i <file>, --input <file>: Input file to process\n");
	printf("\nADDITIONAL OPTIONS:\n");
	printf("\t-p <path>, --path <path>: Injection path\n");
	printf("\t-o <file>, --output <file>: Ouput file. If not set, default to '%s'\n", DEFAULT_OUT_NAME);
	printf("\t-v[vv], --verbose=level: Verbose level. Any additional 'v' adds one level. \n");
}




static void process_configuration(char **argv) {

	// If verbose is not set, this line will not print
	hnotice(1, "Verbose mode active\n");

	// Early check on input file
	if(config.input == NULL) {
		display_usage(argv);
		herror(true, "Input file must be specified\n");
	}

	// Early check on configuration file
	if(config.rules_file == NULL) {
		display_usage(argv);
		herror(true, "Configuration-rules file must be specified\n");
	}

	// Load the configuration file
	hnotice(1, "Loading configuration file '%s'... \n", config.rules_file);
	config.nExecutables = parseRuleFile(config.rules_file, &config.rules);

	hsuccess();
}




static bool parse_cmd_line(int argc, char **argv) {
	int c;
	int option_index;

    	if(argc < 3) {
		display_usage(argv);
		return false;
    	}

	while ((c = getopt_long(argc, argv, "c:p:vi:o:", long_options, &option_index)) != -1) {

		switch (c) {

			case 'c':	// config
				config.rules_file = optarg;
				break;

			case 'p':	// path
				config.inject_path = optarg;
				break;

			case 'v':	// verbose
				if (optarg)
					config.verbose = atoi(optarg);	// --verbose=level
				else
					config.verbose++;	// -v , --verbose
				break;

			case 'i':	// input
				config.input = optarg;
				break;

			case 'o':	// output
				config.output = optarg;
				break;

			case 0:
			case '?':
			default:
				display_usage(argv);
				herror(true, "Invalid options\n");
		}
	}

	if(!config.output) {
		config.output = "final.o";
	}

	return true;
}


/**
 * Links all the additional modules that can be found in the
 * current working directory.
 */
static void link_modules(void) {	
	hnotice(1, "Link additional modules in '%s' to the output instrumented file 'hijacked.o'\n", TEMP_PATH);

	// Step 1: link libhijacker
	link("__temp.o", "-r", "-L", LIBDIR, "-o", "__temp_libhijacked.o", "-lhijacker");
	
	// Step 2: link other injected modules
	if(file_exists("incremental.o")) {
		link("__temp_libhijacked.o", "-r", "-L", LIBDIR, "incremental.o", "-o", config.output);
	} else {
		rename("__temp_libhijacked.o", config.output);
	}

	unlink("__temp.o");
	unlink("__temp_libhijacked.o");
	unlink("incremental.o");
	hsuccess();
}


int main(int argc, char **argv) {

	// Welcome! :)
	hhijacker();

	// Parse configuration
	if(!parse_cmd_line(argc, argv)) {
		exit(EXIT_FAILURE);
	}

	// Process the specified command-line configuration
	process_configuration(argv);

	// Load executable and build a map in memory
	load_program(config.input);

	// Process executable
	apply_rules();

	// Write back executable
	output_object_file("__temp.o");

	// Finalize the output file by linking the module
	link_modules();

	hprint("File ELF written in '%s'\n", config.output);

	exit(EXIT_SUCCESS);
}
