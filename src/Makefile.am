ACLOCAL_AMFLAGS = -I m4
AM_MAKEFLAGS = --no-print-directory
AM_CFLAGS = -I . -I executables -I instructions -I rules -DLIBDIR=\"$(libdir)\"

bin_PROGRAMS = hijacker

hijacker_SOURCES =	main.c \
			loadrules.c \
			utils.c \
			executables/create.c \
			executables/load.c \
			executables/elf/emit-elf.c \
			executables/elf/handle-elf.c \
			executables/elf/parse-elf.c \
			executables/elf/reverse-elf.c \
			rules/apply-rules.c \
			rules/insert_insn.c \
			instructions/block.c \
			instructions/x86/emit-x86.c \
			instructions/x86/parse-x86.c \
			instructions/x86/reverse-x86.c

lib_LIBRARIES = libhijacker.a
libhijacker_a_SOURCES = rules/trampoline64.S
