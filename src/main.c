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
#include <string.h>
#include <getopt.h>

#include <init.h>
#include <utils.h>
#include <config.h>
// #include <options.h>
// #include <prints.h>
// #include <compile.h>
#include <rules/load-rules.h>
#include <rules/apply-rules.h>

// List of registered presets
#include <smtracer/smtracer.h>


/// Global configuration object
configuration config;


// An option array which drives the recognition of command-line
// arguments through the 'getopt' library.
static struct option long_options[] = {
	{"config"  , required_argument, 0, 'c'},
	{"path"    , required_argument, 0, 'p'},
	{"verbose" , optional_argument, 0, 'v'},
	{"input"   , required_argument, 0, 'i'},
	{"output"  , required_argument, 0, 'o'},
	{0         , 0                , 0,  0 }
};


/**
 * Displays the command-line help text. This function is invoked
 * whenever Hijacker fails to recognize command-line arguments.
 */
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


/**
 * Processes the passed configuration file and finalizes the
 * global configuration object.
 */
static void process_configuration(char **argv) {
	// If verbose is not set, this line will not print
	hprint("Verbose mode active\n");

	// Early check on input file
	if(config.input_file == NULL) {
		display_usage(argv);
		herror(true, "Input file must be specified\n");
	}
	else if(!file_exists(config.input_file)) {
		display_usage(argv);
		herror(true, "Unable to find the requested input file\n");
	}

	// Early check on configuration file
	if(config.rules_file == NULL) {
		display_usage(argv);
		herror(true, "Configuration-rules file must be specified\n");
	}
	else if(!file_exists(config.rules_file)) {
		display_usage(argv);
		herror(true, "Unable to find the requested configuration-rules file\n");
	}

	// Early check on output file
	if(config.output_file == NULL) {
		display_usage(argv);
		herror(true, "Output file must be specified\n");
	}

	// Load the configuration file
	hprint("Loading configuration file '%s'... \n", config.rules_file);
	config.nVersions = parseRuleFile(config.rules_file, &config.versions);

	hsuccess();
}


/**
 * Parses the command-line arguments according to the previously
 * defined option array and populates the global configuration
 * object accordingly.
 */
static bool parse_cmd_line(int argc, char **argv) {
	int c;
	int option_index;

	if(argc < 3) {
		display_usage(argv);
		return false;
	}

	while ((c = getopt_long(argc, argv, "c:p:vi:o:", long_options, &option_index)) != -1) {

		switch (c) {
			// config
			case 'c':
				config.rules_file = optarg;
				break;

			// path
			case 'p':
				config.inject_path = optarg;
				break;

			// verbose
			case 'v':
				if (optarg) {
					// --verbose=level
					config.verbose = atoi(optarg);
				} else {
					// -v , --verbose
					config.verbose++;
				}
				break;

			// input
			case 'i':
				config.input_file = optarg;
				break;

			// output
			case 'o':
				config.output_file = optarg;
				break;

			case 0:
			case '?':
			default:
				display_usage(argv);
				herror(true, "Invalid options\n");
		}
	}

	if(!config.output_file) {
		config.output_file = "final.o";
	}

	return true;
}


/**
 * Registers all the available presets so that they can be later
 * used while applying rules.
 */
static void register_presets(void) {
	hprint("Registering presets...\n");

	// So far `smtracer` is the only available preset
	preset_register(PRESET_SMTRACER, smt_init, smt_run);

	hsuccess();
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
		link("__temp_libhijacked.o", "-r", "-L", LIBDIR, "incremental.o", "-o", config.output_file);
	} else {
		rename("__temp_libhijacked.o", config.output_file);
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

	// Register all the available presets
	register_presets();

	// Load executable and build a map in memory
	load_program(config.input_file);

	// Process executable
	apply_rules();

	// Write back executable
	output_object_file("__temp.o");

	// Finalize the output file by linking the module
	link_modules();

	hprint("File ELF written in '%s'\n", config.output_file);

	exit(EXIT_SUCCESS);
}
