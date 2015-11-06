#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdio.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>

#include <bfd.h>
#include <dis-asm.h>

struct asm_insn {
	char mnemonic[16];
	char src[32];
	char dest[32];
	char arg[32];
} curr_insn;

int disprintf(FILE *stream, const char *format, ...) {
	va_list args;
	char *str;

	va_start(args, format);
	str = va_arg(args, char *);

	// libopcodes passes one mnem/operand per call, and src twice!
	if(!curr_insn.mnemonic[0]) {
		strncpy(curr_insn.mnemonic, str, 15);
	} else if(!curr_insn.src[0]) {
		strncpy(curr_insn.src, str, 31);
	} else if(!curr_insn.dest[0]) {
		strncpy(curr_insn.dest, str, 31);
		if(strncmp(curr_insn.dest, "DN", 2) == 0)
			curr_insn.dest[0] = '\0';
	} else {
		if(!strcmp(curr_insn.src, curr_insn.dest)) {
			// src was passed twice
			strncpy(curr_insn.dest, str, 31);
		} else {
			strncpy(curr_insn.arg, str, 31);
		}
	}
	va_end(args);

	return 0;
}

void print_insn(void) {
	printf("\t%s", curr_insn.mnemonic);
	if(curr_insn.src[0]) {
		printf("\t%s", curr_insn.src);
		if(curr_insn.dest[0]) {
			printf(", %s", curr_insn.dest);
			if(curr_insn.arg[0]) {
				printf(", %s", curr_insn.arg);
			}
		}
	}
}

int disassemble_forward(disassembler_ftype disassemble_fn, disassemble_info *info, unsigned long rva) {
	int bytes = 0;

	while(bytes < info->buffer_length) {
		// call libopcodes disassembler
		memset(&curr_insn, 0, sizeof(struct asm_insn));
		bytes += (*disassemble_fn)(info->buffer_vma + bytes, info);

		printf("%8x: ", info->buffer_vma + bytes);
		print_insn();
		printf("\n");
	}

	return bytes;
}

int disassemble_buffer(disassembler_ftype disassemble_fn, disassemble_info *info) {
	int i, size, bytes = 0;

	while(bytes < info->buffer_length) {
		// call libopcodes disassembler
		memset(&curr_insn, 0, sizeof(struct asm_insn));
		size = (*disassemble_fn)(info->buffer_vma + bytes, info);

		// analyze disassembled instruction here
		
		// print symbol names
		printf("%8x:   ", info->buffer_vma + bytes);
		for(i = 0; i < 0; i ++) {
			if(i < size)
				printf("%02x ", info->buffer[bytes + i]);
			else
				printf("   ");
		}
		print_insn();

		printf("\n");
		bytes += size;
	}
	return bytes;
}

static void disassemble(bfd *b, asection *s, unsigned char *buf, int size, unsigned long buf_vma) {
	disassembler_ftype disassemble_fn;
	static disassemble_info info = {0};

	if(!buf)
		return;

	if(!info.arch) {
		// initialize everything
		INIT_DISASSEMBLE_INFO(info, stdout, disprintf);
		info.arch = bfd_get_arch(b);
		info.mach = bfd_mach_i386_i386; /* BFD_guess ? */
		info.flavour = bfd_get_flavour(b);
		info.endian = b->xvec->byteorder;

		/* Queste sono tutte funzioni che possono essere reindirizzate. Forse 
		 * è proprio questo il punto in cui possiamo svoltare l'uso di libopcodes...
		 *
		 * info.read_memory_func = buffer_read_memory;
		 * info.memory_error_func = perror_memory;
		 * info.print_address_func = generic_print_address;
		 * info.symbol_at_address_func = generic_symbol_at_address;
		 * info.symbol = NULL // non capisco a cosa serve questo
		 * info.num_symbol = 0; // come sopra
		 */
		info.display_endian = BFD_ENDIAN_LITTLE;

	}

	// Choose disassembler funcion (non capisco perché non si può fare in automatico con bfd_qualcosa)
	disassemble_fn = print_insn_i386_att;
	//disassemble_fn = print_insn_i386_intel; // che cambia dall'altra?
	
	// per impostare le sezioni
	info.section = s;
	info.buffer = buf;
	info.buffer_length = size;
	info.buffer_vma = buf_vma;

	disassemble_buffer(disassemble_fn, &info);

}


static void print_section_header(asection *s, const char *mode) {

	printf("Disassembly of section %s as %s\n", s->name, mode);
	printf("RVA: %08x LMA: %08x FLAGS: %08x Size: %x\n", s->vma, s->lma, s->flags, s->size);
	printf("------------------------------\n");

}

static void disasm_section_code(bfd *b, asection *section) {
	int size;
	unsigned char *buf;

	size = bfd_section_size(b, section);
	buf = calloc(size, 1);
	if(!buf || !bfd_get_section_contents(b, section, buf, 0, size))
		return;

	print_section_header(section, "code");
	disassemble(b, section, buf, size, section->vma);
	printf("\n\n");
	free(buf);
}

static void disasm_section_data(bfd *b, asection *section) {
	int i, j, size;
	unsigned char *buf;

	size=bfd_section_size(b, section);
	buf = calloc(size, 1);
	if(!bfd_get_section_contents(b, section, buf, 0, size))
		return;

	print_section_header(section, "data");

	// hex dump
	for(i = 0; i < size; i += 16) {
		printf("%08x:    ", section->vma + i);
		for(j = 0; j < 16 && j+i < size; j++)
			printf("%02x ", buf[i+j]);
		for(; j < 16; j++)
			printf("   ");
		printf("    ");
		for(j = 0; j < 16 && j+1 < size; j++)
			printf("%c", isprint(buf[i+j]) ? buf[i+j] : '.');
		printf("\n");
	}
	printf("\n\n");
	free(buf);
}

static void disasm_section(bfd *b, asection *section, PTR data) {
	if(!section->flags & SEC_ALLOC)
		return;
	if(!section->flags & SEC_LOAD)
		return;
	if(section->flags & SEC_LINKER_CREATED)
		return;
	if(section->flags & SEC_CODE) {
		if(!strncmp(".plt", section->name, 4) ||
		   !strncmp(".got", section->name, 4)) 
			return;
		disasm_section_code(b, section);

	} else if( (section->flags & SEC_DATA || section->flags & SEC_READONLY) && section->flags & SEC_HAS_CONTENTS ) {
		disasm_section_data(b, section);
	}

}

int main(int argc, char **argv) {
	struct stat s;
	bfd *infile;

	if(argc < 2) {
		fprintf(stderr, "USage: %s target\n", argv[0]);
		exit(EXIT_FAILURE);
	}
	if(stat(argv[1], &s)) {
		fprintf(stderr, "Error: %s\n", strerror(errno));
		exit(EXIT_FAILURE);
	}

	bfd_init();

	infile = bfd_openr(argv[1], NULL);
	if(!infile) {
		bfd_perror("Error on infile");
		exit(EXIT_FAILURE);
	}

	if(bfd_check_format(infile, bfd_object))
		bfd_map_over_sections(infile, disasm_section, NULL);
	else {
		fprintf(stderr, "Error: file format not supported\n");
		exit(EXIT_FAILURE);
	}

	bfd_close(infile);

	return 0;
}

