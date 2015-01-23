AM_MAKEFLAGS = --no-print-directory
AM_CFLAGS = -I . -I executables -I instructions -I rules

bin_PROGRAMS = hijacker
hijacker_SOURCES =	main.c \
			loadrules.c \
			utils.c \
			executables/create.c \
			executables/load.c \
			executables/coff/emit-coff.c \
			executables/coff/parse-coff.c \
			executables/elf/emit-elf.c \
			executables/elf/handle-elf.c \
			executables/elf/parse-elf.c \
			executables/elf/reverse-elf.c \
			executables/pe/emit-pe.c \
			executables/pe/parse-pe.c \
			rules/apply-rules.c \
			rules/insert_insn.c \
			rules/reverse-instrument.c \
			instructions/alpha/emit-alpha.c \
			instructions/alpha/parse-alpha.c \
			instructions/arm/emit-arm.c \
			instructions/arm/parse-arm.c \
			instructions/ia_64/emit-ia_64.c \
			instructions/ia_64/parse-ia_64.c \
			instructions/mips/emit-mips.c \
			instructions/mips/parse-mips.c \
			instructions/powerpc/emit-powerpc.c \
			instructions/powerpc/parse-powerpc.c \
			instructions/sparc/emit-sparc.c \
			instructions/sparc/parse-sparc.c \
			instructions/x86/emit-x86.c \
			instructions/x86/parse-x86.c \
			instructions/x86/reverse-x86.c
