#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>
#include <string.h>


#include <hijacker.h>
#include <options.h>
#include <rules.h>
#include <prints.h>
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


	// Load the configuration file  TODO reinserire dopo che si è modificato loadrules.c
/*	hnotice(1, "Loading configuration file '%s'... ", config.rules_file);
	config.rules = parseRuleFile(config.rules_file);
	if(config.rules == NULL) {
		hfail();
		herror(true, "Unable to open configuration file '%s'\n", config.rules_file);
	}
*/
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

	return true;
}




int main(int argc, char **argv) {

	bzero(&config, sizeof(configuration));

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
	output_object_file(config.output, 0);

	// finalize the output file by linking the module
	link_module();

	// TODO: Free Rules (?)
	// TODO: Free Executable

	exit(EXIT_SUCCESS);
}

