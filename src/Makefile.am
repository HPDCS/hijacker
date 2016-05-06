ACLOCAL_AMFLAGS = -I m4
AM_MAKEFLAGS = --no-print-directory
AM_CFLAGS = -I . -I executables -I instructions -I rules -I ibr -I presets -DLIBDIR=\"$(libdir)\"

bin_PROGRAMS = hijacker

hijacker_SOURCES =  main.c \
            utils.c \
            executables/create.c \
            executables/load.c \
            ibr/instruction.c \
            ibr/symbol.c \
            ibr/function.c \
            ibr/section.c \
            ibr/block.c \
            executables/elf/emit-elf.c \
            executables/elf/handle-elf.c \
            executables/elf/parse-elf.c \
            executables/elf/reverse-elf.c \
            rules/load-rules.c \
            rules/apply-rules.c \
            instructions/x86/emit-x86.c \
            instructions/x86/parse-x86.c \
            instructions/x86/reverse-x86.c \
            presets/presets.c \
            presets/smtracer/smtracer.c

lib_LIBRARIES = libhijacker.a
libhijacker_a_SOURCES = rules/trampoline64.S
