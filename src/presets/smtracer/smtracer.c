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
* @file smtracer.c
* @brief Selective expression-based memory tracer preset
* @author Simone Economo
*/

#include <stdint.h>
#include <string.h>
#include <math.h>

#include <hijacker.h>
#include <prints.h>
#include <ibr.h>

#include <elf/elf-defs.h>
#include <elf/handle-elf.h>

#include <smtracer/smtracer.h>



// Size of a single entry in the TLS buffer
#define BUFFER_ENTRY_SIZE (1<<4)
// Maximum length for the name of the TLS buffer symbol
#define BUFFER_NAME_LEN   (1<<6)

// Experimental score triple to derive the
// instrumentation score of a single access
#define SCORE_1   1
#define SCORE_2   3
#define SCORE_3   5


// Globals
static section *tbss_sec;
static symbol *tbss_sym;
static symbol *tls_buffer_sym;
static size_t tls_buffer_size;


// Parameters
static double blk_score_threshold;
static size_t chunk_size;
static double acc_threshold;
static bool use_stack;



inline static bool smt_is_relevant(insn_info *instr) {
  bool is_relevant;

  insn_info_x86 *target_x86;
  // symbol *sym;

  if (instr == NULL) {
    return false;
  }

  target_x86 = &instr->i.x86;
  // sym = instr->reference;

  if (use_stack == false) {
    if (target_x86->has_base_register == true && target_x86->breg == 5) {
      return false;
    }
  }

  // A relevant instruction is a memory read/write operation,
  // an indirect memory address computation (e.g. LEA),
  // plus every instruction which refers to a symbol which is either
  // in global data regions (i.e. .data, .bss, .rodata)
  // or thread-local ones (i.e. .tdata, .tbss)

  is_relevant = IS_MEMRD(instr) || IS_MEMWR(instr) /* || IS_MEMIND(instr) */;
  // is_relevant = is_relevant || (sym && sym->type == SYMBOL_VARIABLE);
  // is_relevant = is_relevant || (sym && sym->type == SYMBOL_TLS);

  return is_relevant;
}

static void smt_tls_init(void) {
  void *tbss_payload;
  unsigned int tbss_size;

  unsigned int disp;

  char *buffer_name;

  Section_Hdr *hdr;
  Elf64_Shdr *hdr64;
  Elf32_Shdr *hdr32;

  tbss_size = BUFFER_ENTRY_SIZE * tls_buffer_size;
  disp = 0;

  tbss_sec = find_section_by_name(".tbss");

  if (tbss_sec == NULL) {
    // If the section hasn't been found, it's time to create it
    hnotice(3, "Creating a new .tbss section\n");

    tbss_payload = calloc(tbss_size, 1);

    tbss_sec = section_create(".tbss", SECTION_TLS, tbss_payload);

    section_append(tbss_sec, &PROGRAM(sections)[0]);

    tbss_sym = tbss_sec->sym;

    // Now install a new ELF header...
    hdr = calloc(sizeof(Section_Hdr), 1);

    if (ELF(is64)) {
      hdr64 = &(hdr->section64);

      // hdr64->sh_name = elf_write_string(shstrtab, ".tbss");
      hdr64->sh_type = SHT_NOBITS;
      hdr64->sh_flags = SHF_WRITE | SHF_ALLOC | SHF_TLS;
      hdr64->sh_link = SHN_UNDEF;
      hdr64->sh_addralign = BUFFER_ENTRY_SIZE;
      hdr64->sh_size = tbss_size;
    } else {
      hdr32 = &(hdr->section32);

      // hdr32->sh_name = elf_write_string(shstrtab, ".tbss");
      hdr32->sh_type = SHT_NOBITS;
      hdr32->sh_flags = SHF_WRITE | SHF_ALLOC | SHF_TLS;
      hdr32->sh_link = SHN_UNDEF;
      hdr32->sh_addralign = BUFFER_ENTRY_SIZE;
      hdr32->sh_size = tbss_size;
    }

    tbss_sec->header = hdr;

  } else {
    // Otherwise, let's hook to the existing section
    tbss_sym = find_symbol_by_name(".tbss");

    hnotice(3, "Existing .tbss section found of size %u bytes\n", tbss_sym->size);

    tbss_size += tbss_sym->size;
    tbss_payload = calloc(tbss_size, 1);

    // Update header information...
    hdr = tbss_sec->header;

    if (ELF(is64)) {
      hdr64 = &(hdr->section64);
      disp = hdr64->sh_size;

      hdr64->sh_size = tbss_size;
    } else {
      hdr32 = &(hdr->section32);
      disp = hdr32->sh_size;

      hdr32->sh_size = tbss_size;
    }
  }

  // Update globals
  tbss_sec->payload = tbss_sec->ptr = tbss_payload;
  tbss_sec->name = ".tbss";

  tbss_sym->size = tbss_size;
  tbss_sym->sec = tbss_sec;

  // A different buffer symbol is created for each version
  buffer_name = malloc(BUFFER_NAME_LEN);
  sprintf(buffer_name, "__smtracer_buffer_%d", PROGRAM(version));

  tls_buffer_sym = symbol_create(buffer_name, SYMBOL_TLS, SYMBOL_LOCAL, tbss_sec,
    BUFFER_ENTRY_SIZE * tls_buffer_size);

  tls_buffer_sym->offset = disp;
  tls_buffer_sym->secnum = tbss_sec->index;
}

static bool smt_collect_loop_headers(void *elem, void *data) {
  block_edge *edge = elem;
  linked_list *headers = data;

  if (edge->to->visited == false && edge->to->type == BLOCK_LOOP_HEADER) {
    ll_push(headers, edge->to);
  }

  return true;
}

static bool smt_discover_loop_body(void *elem, void *data) {
  block_edge *edge = elem;
  block *header = data;

  smt_data *smt;

  smt = edge->from->smtracer;

  // Stop the visit as soon as we're exiting the cycle
  if (edge->to == header && edge->dir == EDGE_NEXT) {
    return false;
  }

  // If the current block hasn't been visited yet, register its loop header
  if (edge->from->visited == false && edge->from != header) {
    smt->lheader = header;
  }

  // Do not enter inner loops, it will be done in a dedicated visit
  if (edge->from->type == BLOCK_LOOP_HEADER && edge->from != header) {
    return false;
  }

  return true;
}

static void smt_compute_cycles(void) {
  linked_list headers;
  block *blk, *header;
  smt_data *smt;
  function *func;
  ll_node *caller, *called;

  // First step: collect loop headers
  hnotice(3, "Collecting loop headers...\n");

  ll_init(&headers);

  for (func = PROGRAM(v_code)[PROGRAM(version)]; func; func = func->next) {
    graph_visit visit = {
      .payload   = &headers,
      .policy    = VISIT_DEPTH,
      .dir       = VISIT_FORWARD,
      .pre_func  = smt_collect_loop_headers,
      .post_func = NULL
    };

    block_graph_visit(func->source->in.first->elem, &visit);
  }

  // Second step: discover loop bodies
  hnotice(3, "Discovering loop bodies...\n");

  while (!ll_empty(&headers)) {
    header = ll_pop(&headers);

    block_edge edge = { EDGE_INIT, EDGE_NEXT, header, NULL };
    graph_visit visit = {
      .payload   = header,
      .policy    = VISIT_DEPTH,
      .dir       = VISIT_BACKWARD,
      .pre_func  = smt_discover_loop_body,
      .post_func = NULL
    };

    block_graph_visit(&edge, &visit);
  }

  // Third step: compute the number of cycles a block participates to
  hnotice(3, "Computing cycles feature...\n");

  for (blk = PROGRAM(blocks)[PROGRAM(version)]; blk; blk = blk->next) {
    smt = blk->smtracer;

    // A loop header participates in its own loop
    if (blk->type == BLOCK_LOOP_HEADER) {
      smt->cycles += 1;
    }

    header = smt->lheader;
    while (header) {
      smt->cycles += 1;
      header = ((smt_data *)header->smtracer)->lheader;
    }

    hnotice(6, "Block #%u participates to %u cycles...\n", blk->id, smt->cycles);
  }

  // Fourth step: ride CALL instructions to see if some blocks actually
  // participate to a higher number of cycles across function calls
  hnotice(3, "Extending cycle feature to block across different functions...\n");

  unsigned int hottest;
  linked_list queue = { NULL, NULL };

  for (func = PROGRAM(v_code)[PROGRAM(version)]; func; func = func->next) {
    if (func->calledfrom.first == NULL) {
      ll_push(&queue, func);
    }
  }

  while(!ll_empty(&queue)) {
    func = ll_pop(&queue);
    hottest = 0;

    if (func->visited == true) {
      continue;
    } else {
      func->visited = true;
    }

    for (caller = func->calledfrom.first; caller; caller = caller->next) {
      blk = caller->elem;
      smt = blk->smtracer;

      hnotice(3, "Caller block #%u for function '%s' participates to %u cycles\n",
        blk->id, func->name, smt->cycles);

      if (hottest < smt->cycles) {
        hottest = smt->cycles;
      }
    }

    hnotice(3, "Cycle feature will be extended by %u in func '%s'\n",
      hottest, func->name);

    for (blk = func->begin_blk; blk != func->end_blk->next; blk = blk->next) {
      smt = blk->smtracer;

      smt->cycles += hottest;
    }

    for (called = func->callto.first; called; called = called->next) {
      ll_push(&queue, called->elem);
    }
  }

  for (func = PROGRAM(code); func; func = func->next) {
    func->visited = false;
  }
}

static void smt_compute_memratio(void) {
  block *blk;
  smt_data *smt;

  insn_info *pivot;
  bool is_relevant;

  size_t memcount, highest;

  highest = 0;

  for (blk = PROGRAM(blocks)[PROGRAM(version)]; blk; blk = blk->next) {
    smt = blk->smtracer;
    memcount = 0;

    for (pivot = blk->begin; pivot != blk->end->next; pivot = pivot->next) {
      is_relevant = smt_is_relevant(pivot);

      if (is_relevant) {
        memcount += 1;
      }
    }

    smt->memratio = memcount * memcount / blk->length;

    if (highest < memcount) {
      highest = memcount;
    }
  }

  highest = highest > 0 ? highest : 1;

  for (blk = PROGRAM(blocks)[PROGRAM(version)]; blk; blk = blk->next) {
    smt = blk->smtracer;

    smt->memratio /= highest;
  }
}

static void smt_compute_features(void) {
  block *blk;
  smt_data *smt;
  float highest;

  // Blocks are augmented with extra information
  for (blk = PROGRAM(blocks)[PROGRAM(version)]; blk; blk = blk->next) {
    hnotice(6, "Allocating memory for smtracer at block #%u\n", blk->id);

    blk->smtracer = calloc(sizeof(smt_data), 1);
  }

  // Features are computed
  smt_compute_cycles();
  smt_compute_memratio();

  // The total absolute score is computed for each block
  highest = 0;

  for (blk = PROGRAM(blocks)[PROGRAM(version)]; blk; blk = blk->next) {
    smt = blk->smtracer;

    smt->score = (smt->cycles + 1) * smt->memratio;

    if (highest < smt->score) {
      highest = smt->score;
    }
  }

  // The total relative score is computed based on the highest absolute one
  for (blk = PROGRAM(blocks)[PROGRAM(version)]; blk; blk = blk->next) {
    smt = blk->smtracer;

    if (highest == 0) {
      smt->score = 1.0;
    }
    else {
      smt->score /= highest;
    }
  }
}

void smt_init(void) {
  function *func;
  insn_info *instr;
  size_t count, highest;

  // Detect the maximum size for the TLS buffer so that
  // no relevant access will be discarded due to lack of space
  highest = 0;

  for (func = PROGRAM(code); func; func = func->next) {
    count = 0;

    for (instr = func->begin_insn; instr; instr = instr->next) {
      count += smt_is_relevant(instr);
    }

    if (count > highest) {
      highest = count;
    }
  }

  tls_buffer_size = highest;

  // The application's IBR is augmented with TLS-enabling sections and symbols
  // that allow the instrumented logic to store data into the application's
  // address space
  smt_tls_init();

  // Block-level features are computed to later instrument basic blocks according
  // to user-defined blk_score_thresholds
  smt_compute_features();
}

inline static bool smt_is_flushpoint(insn_info *instr, function *func) {
  bool is_flushpoint;

  // A flushpoint is a call to a local function plus the first instruction of the
  // last basic block for the current function

  is_flushpoint = IS_CALL(instr);
  is_flushpoint = is_flushpoint && (instr->jumpto || instr->jumptable.size > 0);
  is_flushpoint = is_flushpoint || instr == func->end_blk->begin;

  return is_flushpoint;
}

static void smt_resolve_address(smt_access *access) {
  insn_info *pivot, *current;
  insn_info_x86 *x86;
  symbol *sym, *ref;

  pivot = access->insn;
  x86 = &pivot->i.x86;
  sym = pivot->reference;

  bool has_disp, has_fs;
  unsigned char scale, modrm, sib;

  hnotice(3, "Resolving address of memory reference in '%s' at <%#08llx> with %lld + (%u + %u * %lu)\n",
    pivot->i.x86.mnemonic, pivot->orig_addr, x86->disp, x86->breg, x86->ireg, x86->scale);

  has_disp = true;
  has_fs = x86->insn[0] == 0x64;

  switch(x86->scale) {
    case 8:
      scale = 3;
      break;

    case 4:
      scale = 2;
      break;

    case 2:
      scale = 1;
      break;

    case 1:
    default:
      scale = 0;
      break;
  }

  // We replace the source/destination register with %rsi
  modrm = (x86->modrm & 0xc7) | 0x30;
  sib = x86->sib;

  if (modrm >= 0x40 && modrm <= 0x7f) {
    // disp8 gets replaced with disp32
    modrm += 0x40;
  }
  else if (modrm <= 0x3f) {
    // Neither disp8 nor disp32
    has_disp = false;
  }

  if (sym == NULL) {
    // No relocation, therefore it's likely to be a heap access
    // or a base TLS address loading (e.g. MOV %fs:0x0, %reg)
    hnotice(3, "Instruction carries no relocation\n");

    if (has_disp == false) {

      if (sib != 0) {

        if (has_fs == true) {
          unsigned char instr[9] = {
            0x64, 0x48, 0x8b, modrm, sib, 0x00, 0x00, 0x00, 0x00
          };

          insert_instructions_at(pivot, instr, sizeof(instr), INSERT_BEFORE, NULL);
        } else {

          if (x86->has_base_register == true) {
            modrm += 0x80;
          } else {
            // It is probably a LEA used for fast arithmetic computation,
            // therefore it is discarded
          }

          unsigned char instr[8] = {
            0x48, 0x8d, modrm, sib, 0x00, 0x00, 0x00, 0x00
          };

          insert_instructions_at(pivot, instr, sizeof(instr), INSERT_BEFORE, NULL);
        }

      } else {

        unsigned char instr[3] = {
          0x48, 0x8d, modrm
        };

        insert_instructions_at(pivot, instr, sizeof(instr), INSERT_BEFORE, NULL);

      }

    }

    else {

      if (sib != 0) {

        unsigned char instr[8] = {
          0x48, 0x8d, modrm, sib, 0x00, 0x00, 0x00, 0x00
        };

        *(uint32_t *)(instr + 4) = x86->disp;

        insert_instructions_at(pivot, instr, sizeof(instr), INSERT_BEFORE, NULL);

      } else {

        unsigned char instr[7] = {
          0x48, 0x8d, modrm, 0x00, 0x00, 0x00, 0x00
        };

        *(uint32_t *)(instr + 3) = x86->disp;

        insert_instructions_at(pivot, instr, sizeof(instr), INSERT_BEFORE, NULL);

      }

    }

  } else {
    hnotice(3, "Instruction has relocation information of type %u\n", sym->relocation.type);

    if (sym->relocation.type == R_X86_64_PC32) {
      unsigned char instr[7] = {
        0x48, 0x8d, 0x35, 0x00, 0x00, 0x00, 0x00
      };

      insert_instructions_at(pivot, instr, sizeof(instr), INSERT_BEFORE, &current);

      ref = symbol_instr_rela_create(sym, current, RELOC_PCREL_32);
      // ref->relocation.addend = sym->relocation.addend;
    }

    else if (sym->relocation.type == R_X86_64_32 || sym->relocation.type == R_X86_64_32S) {
      unsigned char instr[7] = {
        0x48, 0xc7, 0xc6, 0x00, 0x00, 0x00, 0x00
      };

      insert_instructions_at(pivot, instr, sizeof(instr), INSERT_BEFORE, &current);

      ref = symbol_instr_rela_create(sym, current, RELOC_ABS_32);
      // ref->relocation.addend = sym->relocation.addend;

      if (sym->relocation.type == R_X86_64_32S) {
        ref->relocation.type = R_X86_64_32S;
      }
    }

    else if (sym->relocation.type == R_X86_64_64) {
      unsigned char instr[10] = {
        0x48, 0xbe, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
      };

      insert_instructions_at(pivot, instr, sizeof(instr), INSERT_BEFORE, &current);

      ref = symbol_instr_rela_create(sym, current, RELOC_ABS_64);
      // ref->relocation.addend = sym->relocation.addend;
    }

    else if (sym->relocation.type == R_X86_64_TPOFF32) {

      if (has_fs) {
        // We are using the %fs register to displace into a TLS area

        {
          unsigned char instr[9] = {
            0x64, 0x48, 0x8b, 0x34, 0x25, 0x00, 0x00, 0x00, 0x00
          };

          insert_instructions_at(pivot, instr, sizeof(instr), INSERT_BEFORE, &current);
        }

        {
          unsigned char instr[7] = {
            0x48, 0x8d, 0xb6, 0x00, 0x00, 0x00, 0x00
          };

          insert_instructions_at(pivot, instr, sizeof(instr), INSERT_BEFORE, &current);
        }
      } else {
        // We are indirectly displacing into a TLS area using a regular SIB form

        if (sib != 0) {
          unsigned char instr[8] = {
            0x48, 0x8d, modrm, sib, 0x00, 0x00, 0x00, 0x00
          };

          insert_instructions_at(pivot, instr, sizeof(instr), INSERT_BEFORE, &current);
        } else {
          unsigned char instr[7] = {
            0x48, 0x8d, modrm, 0x00, 0x00, 0x00, 0x00
          };

          insert_instructions_at(pivot, instr, sizeof(instr), INSERT_BEFORE, &current);
        }
      }

      ref = symbol_instr_rela_create(sym, current, RELOC_TLSREL_32);
      // ref->relocation.addend = sym->relocation.addend;
    }

    else {

      hinternal();

      // if (sib != 0) {
      //   unsigned char instr[8] = {
      //     0x48, 0x8d, modrm, sib, 0x00, 0x00, 0x00, 0x00
      //   };

      //   insert_instructions_at(pivot, instr, sizeof(instr), INSERT_BEFORE, &current);
      // } else {
      //   unsigned char instr[7] = {
      //     0x48, 0x8d, modrm, 0x00, 0x00, 0x00, 0x00
      //   };

      //   insert_instructions_at(pivot, instr, sizeof(instr), INSERT_BEFORE, &current);
      // }

      // symbol_instr_rela_create(sym, current, RELOC_ABS_64);
    }

  }
}

static void smt_instrument_access(block *blk, smt_access *access) {
  insn_info *pivot, *current, *first;
  symbol *ref;

  pivot = access->insn;
  current = first = NULL;

  // Protect old register values
  // ---------------------------
  // PUSH %rsi

  {
    unsigned char instr[1] = {
      0x56
    };

    insert_instructions_at(pivot, instr, sizeof(instr), INSERT_BEFORE, &current);

    // If the instrumented instruction is the target of a jump, let's update
    // the virtual reference
    // if (pivot == block_find(pivot)->begin && !pivot->virtual) {
    if (!ll_empty(&pivot->targetof) && !pivot->virtual) {
      set_virtual_reference(pivot, current);
    }
  }

  // Resolve memory address
  // ----------------------
  // LEA disp(base, idx, scale), %rsi
  // MOV addr, %rsi
  // MOVABS addr, %rsi

  smt_resolve_address(access);

  // Compute chunk address from memory address
  // -----------------------------------------
  // SHR %rsi, $12
  // SHL %rsi, $12

  {
    unsigned char instr[4] = {
      0x48, 0xc1, 0xee, 0x0c
    };

    insert_instructions_at(pivot, instr, sizeof(instr), INSERT_BEFORE, NULL);
  }

  {
    unsigned char instr[4] = {
      0x48, 0xc1, 0xe6, 0x0c
    };

    insert_instructions_at(pivot, instr, sizeof(instr), INSERT_BEFORE, NULL);
  }

  // Store chunk address in TLS buffer
  // ---------------------------------
  // MOV %rsi, %fs:disp+index*BUFFER_ENTRY_SIZE

  {
    unsigned char instr[9] = {
      0x64, 0x48, 0x89, 0x34, 0x25, 0x00, 0x00, 0x00, 0x00
    };

    insert_instructions_at(pivot, instr, sizeof(instr), INSERT_BEFORE, &current);

    ref = symbol_instr_rela_create(tls_buffer_sym, current, RELOC_TLSREL_32);
    ref->relocation.addend = access->index * BUFFER_ENTRY_SIZE;
  }

  // Increment block id + access counter in TLS buffer
  // -------------------------------------------------
  // MOVQ (blk->id << 16 | access->counter), %rsi
  // ADD %rsi, %fs:disp+index*BUFFER_ENTRY_SIZE+BUFFER_ENTRY_SIZE/2

  {
    unsigned char instr[7] = {
      0x48, 0xc7, 0xc6, 0x00, 0x00, 0x00, 0x00
    };

    // *(uint32_t *)(instr + 3) = access->counter;
    *(uint32_t *)(instr + 3) = blk->id << 16 | access->counter;

    insert_instructions_at(pivot, instr, sizeof(instr), INSERT_BEFORE, &current);
  }

  {
    unsigned char instr[9] = {
      0x64, 0x48, 0x01, 0x34, 0x25, 0x00, 0x00, 0x00, 0x00
    };

    insert_instructions_at(pivot, instr, sizeof(instr), INSERT_BEFORE, &current);

    ref = symbol_instr_rela_create(tls_buffer_sym, current, RELOC_TLSREL_32);
    ref->relocation.addend = access->index * BUFFER_ENTRY_SIZE + BUFFER_ENTRY_SIZE / 2;
  }

  // Restore old register values
  // ---------------------------
  // POP %rsi

  {
    unsigned char instr[1] = {
      0x5e
    };

    insert_instructions_at(pivot, instr, sizeof(instr), INSERT_BEFORE, NULL);
  }
}

static size_t smt_instrument_block(block *blk) {
  smt_data *smt;
  smt_access *access, *highest;

  double similarity;
  double overhead;
  size_t ninstr;
  size_t cinstr;

  // Index in the TLS buffer (function-level scope)
  static size_t index;

  smt = blk->smtracer;

  // We compute the percentage overhead as a function of
  // the number of candidates and the user-defined accuracy
  similarity = smt->ntotal / smt->ncandidates;
  overhead = pow(acc_threshold, similarity);

  // The number of accesses that is actually instrumented
  // is computed using the number of candidates and the
  // overhead
  ninstr = ceil(overhead * smt->ncandidates);
  cinstr = 0;

  hnotice(3, "Instrumentable candidates: %lu; Total candidates: %lu; Total: %lu\n",
    ninstr, smt->ncandidates, smt->ntotal);

  // Keep instrumenting until there's no more space left
  // in our bag full of overhead...
  while(cinstr < ninstr) {
    highest = NULL;

    // Find the next access to instrument according to its score
    for (access = smt->candidates; access; access = access->next) {

      if (highest == NULL && access->instrumented == false) {
        // The first intercepted access is the first occurring
        // access which hasn't been instrumented yet
        highest = access;
      }

      if (highest != NULL && access->instrumented == false) {
        // NOTE: strict inequality, since our bias is toward the
        // first occurring access within the basic block
        if (access->score > highest->score) {
          highest = access;
        }
      }

    }

    if (highest == NULL) {
      // There are no more accesses to instrument
      // NOTE: it should never happen
      hinternal();
      break;
    }

    // Instrument the access
    smt_instrument_access(blk, highest);

    hnotice(3, "Instrumented access '%s' at <%#08llx> (cinstr = %lu)\n",
      highest->insn->i.x86.mnemonic, highest->insn->orig_addr, cinstr);

    highest->instrumented = true;
    highest->index = index;

    index += 1;
    cinstr += 1;

  }

  return cinstr;
}

inline static bool smt_same_breg(smt_access *target, smt_access *current) {
  bool same;
  insn_info_x86 *target_x86, *current_x86;

  target_x86 = &target->insn->i.x86;
  current_x86 = &current->insn->i.x86;

  if (target_x86->has_base_register && current_x86->has_base_register) {
    same = target_x86->breg == current_x86->breg;
    same = same && target->vtable[target_x86->breg] == current->vtable[target_x86->breg];

    return same;
  }

  return false;
}

inline static bool smt_same_ireg(smt_access *target, smt_access *current) {
  bool same;
  insn_info_x86 *target_x86, *current_x86;

  target_x86 = &target->insn->i.x86;
  current_x86 = &current->insn->i.x86;

  if (target_x86->has_index_register && current_x86->has_index_register) {
    same = target_x86->ireg == current_x86->ireg;
    same = same && target->vtable[target_x86->ireg] == current->vtable[target_x86->ireg];

    if (target_x86->has_scale && current_x86->has_scale) {
      same = same && target_x86->scale == current_x86->scale;
    }

    return same;
  }

  return false;
}

inline static size_t smt_absdiff_imm(smt_access *target, smt_access *current) {
  return abs(target->insn->i.x86.disp - current->insn->i.x86.disp);
}

inline static size_t smt_absdiff_sym(smt_access *target, smt_access *current) {
  symbol *target_sym, *current_sym;
  section *target_sec, *current_sec;

  ptrdiff_t distance;

  target_sym = target->insn->reference;
  current_sym = current->insn->reference;

  target_sec = find_section(target_sym->secnum);
  current_sec = find_section(current_sym->secnum);

  if (target_sec == current_sec) {
    // if (target_sym != current_sym) {
      distance = target_sym->offset + target_sym->relocation.addend;
      distance -= current_sym->offset + current_sym->relocation.addend;

      return abs(distance);
    // } else {
    //   return 0;
    // }
  }

  return chunk_size;
}

static inline bool smt_is_irr(smt_access *access) {
  return (access->insn->reference != NULL);
}

static bool smt_same_template(smt_access *target, smt_access *current) {
  symbol *target_sym, *current_sym;

  target_sym = target->insn->reference;
  current_sym = current->insn->reference;

  if (target_sym == current_sym) {
    // When symbols are the same, the two accesses
    // share the same template only when the symbols
    // are NULL (i.e., accesses to dynamic memory)
    return (target_sym == NULL);
  } else {
    // When symbols are different, the two accesses
    // share the same template only when the symbols
    // are non-NULL (i.e., accesses to static memory)
    return (target_sym != NULL && current_sym != NULL);
  }
}

static double smt_likelihood_irr(smt_access *target, smt_access *current) {
  double score;

  score = 0;

  if (smt_absdiff_sym(target, current) >= chunk_size) {
    score += SCORE_3;

    if (smt_same_breg(target, current) == false) {
      score += SCORE_1;
    }

    if (smt_same_ireg(target, current) == false) {
      score += SCORE_2;
    }
  }

  return score;
}

static double smt_likelihood_rri(smt_access *target, smt_access *current) {
  double score;

  score = 0;

  if (smt_same_breg(target, current)) {
    if (smt_same_ireg(target, current)) {
      if (smt_absdiff_imm(target, current) >= chunk_size) {
        score += SCORE_3;
      }
    }
  }

  if (smt_same_breg(target, current) == false) {
    score += SCORE_2;
  }

  if (smt_same_ireg(target, current) == false) {
    score += SCORE_1;
  }

  return score;
}

static void smt_compute_access_scores(block *blk) {
  smt_data *smt;
  smt_access *target, *current;

  smt = blk->smtracer;

  double distance[smt->ncandidates][smt->ncandidates];
  int i, j;

  // We maintain a symmetric matrix of distances to avoid
  // computing the same distance twice
  memset(distance, '\0', sizeof(double) * smt->ncandidates * smt->ncandidates);

  for (i = 0, target = smt->candidates; target; target = target->next, ++i) {

    for (j = 0, current = smt->candidates; current; current = current->next, ++j) {

      if (target == current || distance[i][j] > 0) {
        // If distance[i][j] is greater than zero, then we have
        // already computed the dual case previously
        continue;
      }

      if (smt_same_template(target, current)) {
        if (smt_is_irr(target)) {
          distance[i][j] += smt_likelihood_irr(target, current);
        } else {
          distance[i][j] += smt_likelihood_rri(target, current);
        }
      }

      // The dual case is equivalent, so let's
      // reuse the result to speed-up the algorithm
      distance[j][i] = distance[i][j];

      // Update cumulated distances
      // NOTE: `current` won't ever get here twice when
      // distance[i][j] is greater than zero
      target->score += distance[i][j];
      current->score += distance[i][j];
    }

    // Compute average distance
    if (smt_is_irr(target)) {
      target->score /= smt->nirr;
    } else {
      target->score /= smt->nrri;
    }

    hnotice(3, "Access score for '%s' at <%#08llx> is '%0.2f'\n",
      target->insn->i.x86.mnemonic, target->insn->orig_addr, target->score);
  }
}

static void smt_call_routine(unsigned int total, symbol *callfunc, insn_info *pivot) {
  insn_info *current;

  current = NULL;

  // Protect old register values
  // ---------------------------
  // PUSHF
  // PUSH %rax
  // PUSH %rcx
  // PUSH %rdx
  // PUSH %rsi
  // PUSH %rdi
  // PUSH %r8
  // PUSH %r9
  // PUSH %r10
  // PUSH %r11
  // SUB $16,%rsp
  // MOVSD %xmm0,(%rsp)
  // SUB $16,%rsp
  // MOVSD %xmm1,(%rsp)
  // SUB $16,%rsp
  // MOVSD %xmm2,(%rsp)
  // SUB $16,%rsp
  // MOVSD %xmm3,(%rsp)
  // SUB $16,%rsp
  // MOVSD %xmm4,(%rsp)
  // SUB $16,%rsp
  // MOVSD %xmm5,(%rsp)
  // SUB $16,%rsp
  // MOVSD %xmm6,(%rsp)
  // SUB $16,%rsp
  // MOVSD %xmm7,(%rsp)

  {
    // unsigned char instr[4] = {
    //   0x9c,
    //   0x50,
    //   0x56,
    //   0x57
    // };

    unsigned char instr[86] = {
      0xf2, 0x0f, 0x11, 0x3c, 0x24,
      0x48, 0x83, 0xec, 0x10,
      0xf2, 0x0f, 0x11, 0x34, 0x24,
      0x48, 0x83, 0xec, 0x10,
      0xf2, 0x0f, 0x11, 0x2c, 0x24,
      0x48, 0x83, 0xec, 0x10,
      0xf2, 0x0f, 0x11, 0x24, 0x24,
      0x48, 0x83, 0xec, 0x10,
      0xf2, 0x0f, 0x11, 0x1c, 0x24,
      0x48, 0x83, 0xec, 0x10,
      0xf2, 0x0f, 0x11, 0x14, 0x24,
      0x48, 0x83, 0xec, 0x10,
      0xf2, 0x0f, 0x11, 0x0c, 0x24,
      0x48, 0x83, 0xec, 0x10,
      0xf2, 0x0f, 0x11, 0x04, 0x24,
      0x48, 0x83, 0xec, 0x10,
      0x41, 0x53,
      0x41, 0x52,
      0x41, 0x51,
      0x41, 0x50,
      0x57,
      0x56,
      0x52,
      0x51,
      0x50,
      0x9c,
    };

    insert_instructions_at(pivot, instr, sizeof(instr), INSERT_BEFORE, NULL);
  }

  // Load TLS storage
  // ----------------
  // MOV %fs:0x0, %rdi

  {
    unsigned char instr[9] = {
      0x64, 0x48, 0x8b, 0x3c, 0x25, 0x00, 0x00, 0x00, 0x00
    };

    insert_instructions_at(pivot, instr, sizeof(instr), INSERT_BEFORE, NULL);
  }

  // Displace to TLS buffer
  // ----------------------
  // LEA disp(%rdi), %rdi

  {
    unsigned char instr[7] = {
      0x48, 0x8d, 0xbf, 0x00, 0x00, 0x00, 0x00
    };

    insert_instructions_at(pivot, instr, sizeof(instr), INSERT_BEFORE, &current);

    symbol_instr_rela_create(tls_buffer_sym, current, RELOC_TLSREL_32);
  }

  // Store total number of tracked accesses
  // --------------------------------------
  // MOV total, %rsi

  {
    unsigned char instr[7] = {
      0x48, 0xc7, 0xc6, 0x00, 0x00, 0x00, 0x00
    };

    *(uint32_t *)(instr + 3) = total;

    insert_instructions_at(pivot, instr, sizeof(instr), INSERT_BEFORE, NULL);
  }

  // Store user-defined routine address
  // ----------------------------------
  // MOV routine, %rax

  // {
  //   unsigned char instr[10] = {
  //     0x48, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
  //   };

  //   insert_instructions_at(current, instr, sizeof(instr), INSERT_AFTER, &current);

  //   symbol_instr_rela_create(callfunc, current, RELOC_ABS_64);
  // }

  // Call user-defined routine
  // -------------------------
  // CALL *(%rax)

  // {
  //   unsigned char instr[2] = {
  //     0xff, 0x10
  //   };

  //   insert_instructions_at(current, instr, sizeof(instr), INSERT_AFTER, &current);
  // }

  {
    unsigned char instr[5] = {
      0xe8, 0x00, 0x00, 0x00, 0x00
    };

    insert_instructions_at(pivot, instr, sizeof(instr), INSERT_BEFORE, &current);

    symbol_instr_rela_create(callfunc, current, RELOC_PCREL_32);
  }

  // Restore old register values
  // ---------------------------
  // MOVSD (%rsp), %xmm7
  // ADD $16,%rsp
  // MOVSD (%rsp), %xmm6
  // ADD $16,%rsp
  // MOVSD (%rsp), %xmm5
  // ADD $16,%rsp
  // MOVSD (%rsp), %xmm4
  // ADD $16,%rsp
  // MOVSD (%rsp), %xmm3
  // ADD $16,%rsp
  // MOVSD (%rsp), %xmm2
  // ADD $16,%rsp
  // MOVSD (%rsp), %xmm1
  // ADD $16,%rsp
  // MOVSD (%rsp), %xmm0
  // ADD $16,%rsp
  // POP %r11
  // POP %r10
  // POP %r9
  // POP %r8
  // POP %rdi
  // POP %rsi
  // POP %rdx
  // POP %rcx
  // POP %rax
  // POPF

  {
    // unsigned char instr[4] = {
    //   0x5f,
    //   0x5e,
    //   0x58,
    //   0x9d
    // };

    unsigned char instr[86] = {
      0x9d,
      0x58,
      0x59,
      0x5a,
      0x5e,
      0x5f,
      0x41, 0x58,
      0x41, 0x59,
      0x41, 0x5a,
      0x41, 0x5b,
      0x48, 0x83, 0xc4, 0x10,
      0xf2, 0x0f, 0x10, 0x04, 0x24,
      0x48, 0x83, 0xc4, 0x10,
      0xf2, 0x0f, 0x10, 0x0c, 0x24,
      0x48, 0x83, 0xc4, 0x10,
      0xf2, 0x0f, 0x10, 0x14, 0x24,
      0x48, 0x83, 0xc4, 0x10,
      0xf2, 0x0f, 0x10, 0x1c, 0x24,
      0x48, 0x83, 0xc4, 0x10,
      0xf2, 0x0f, 0x10, 0x24, 0x24,
      0x48, 0x83, 0xc4, 0x10,
      0xf2, 0x0f, 0x10, 0x2c, 0x24,
      0x48, 0x83, 0xc4, 0x10,
      0xf2, 0x0f, 0x10, 0x34, 0x24,
      0x48, 0x83, 0xc4, 0x10,
      0xf2, 0x0f, 0x10, 0x3c, 0x24,
    };

    insert_instructions_at(pivot, instr, sizeof(instr), INSERT_BEFORE, NULL);
  }
}

static void smt_update_vtable(insn_info *instr, char *vtable) {
  insn_info_x86 *x86;

  x86 = &instr->i.x86;

  if (x86->dest_is_reg == true) {
    if (x86->reg_dest >= SMT_VTABLE_SIZE) {
      hinternal();
    }

    vtable[x86->reg_dest] += 1;
  }
}

static bool smt_check_equivalence(smt_access *target, smt_access *current) {
  bool same;

  symbol *target_sym, *current_sym;

  if (smt_same_template(target, current) == false) {
    // Different templates mean non-equivalent accesses
    return false;
  }

  same = true;

  if (smt_is_irr(target)) {
    // Statically-allocated objects
    // ----------------------------
    // Accesses refer to the same symbol, which is associated
    // with relocation information

    target_sym = target->insn->reference;
    current_sym = current->insn->reference;

    if (target_sym != current_sym) {
      // Different existing symbols mean non-equivalent accesses
      // NOTE: The target symbol is implicitly non-NULL here
      return false;
    }

    // For the sake of simplicity, we enforce the same
    // relocation type for equivalent accesses.
    // This is also reflected in the ability to compare
    // two different addends without committing mistakes
    same = same && (target_sym->relocation.type == current_sym->relocation.type);

    // We also need to check the addend, since it is
    // directly aggregated into the displacement value
    // produced by the linker
    same = same && (target_sym->relocation.addend == current_sym->relocation.addend);

    // Accesses to the same symbols, we now check relocation
    // information to further discriminate
    if ( target_sym->relocation.type == R_X86_64_32
      || target_sym->relocation.type == R_X86_64_32S
      || target_sym->relocation.type == R_X86_64_64
      || target_sym->relocation.type == R_X86_64_TPOFF32
      || target_sym->relocation.type == R_X86_64_TPOFF64 ) {
      // Absolute addressing is being used, therefore we
      // must check base and index registers since they
      // can still be specified within the expressions.

      // Checking the base register
      same = same && smt_same_breg(target, current);
      // Checking the index register and the scale
      same = same && smt_same_ireg(target, current);
    }
    else if (target_sym->relocation.type == R_X86_64_PC32) {
      // These accesses use the RIP-relative addressing mode,
      // so checking for the equivalence of symbols is sufficient
      // to evaluate the equivalence of expressions
    }

    return same;
  }

  else {
    // Dynamically-allocated objects
    // -----------------------------
    // Accesses don't refer to any symbol, so we simply
    // check for base, index and displacement equivalence

    // Checking the base register
    same = same && smt_same_breg(target, current);
    // Checking the index register and the scale
    same = same && smt_same_ireg(target, current);
    // Checking the displacement
    same = same && smt_absdiff_imm(target, current) == 0;

    return same;
  }

  return false;
}

static bool smt_resolve_access(block *blk, insn_info *instr, char *vtable) {
  smt_data *smt;
  smt_access *target, *current, *prev;

  smt = blk->smtracer;

  // Access meta-data is created to compare the current
  // access with the accesses already in the history
  target = calloc(sizeof(smt_access), 1);

  target->counter = 1;
  target->insn = instr;
  target->instrumented = false;

  smt->ntotal += 1;

  memcpy(target->vtable, vtable, sizeof(target->vtable));

  // We now scan the entire list of captured accesses to see if there's
  // a duplicate, in which case the new access gets discarded
  prev = NULL;

  for (current = smt->candidates; current; prev = current, current = current->next) {
    if (smt_check_equivalence(target, current)) {
      // If an equivalence access were already intercepted,
      // skip this one and increment the counter of the former,
      // then exit the function
      hnotice(3, "Found equivalence between accesses '%s' and '%s'\n",
        target->insn->i.x86.mnemonic, current->insn->i.x86.mnemonic);

      current->counter += 1;

      free(target);
      return false;
    }
  }

  // We captured a new access, gotcha! It will be later logged into the
  // application's TLS buffer
  hnotice(3, "New access found '%s' at <%#08llx>\n",
    target->insn->i.x86.mnemonic, target->insn->orig_addr);

  if (smt->candidates == NULL) {
    smt->candidates = target;
  } else {
    prev->next = target;
  }

  if (smt_is_irr(target)) {
    smt->nirr += 1;
  } else {
    smt->nrri += 1;
  }

  smt->ncandidates += 1;

  return true;
}

static void smt_trace_block(block *blk) {
  insn_info *instr;

  char vtable[SMT_VTABLE_SIZE];

  // We reset the general-purpose version table at the beginning
  // of a new basic block, as well as the number of
  memset(vtable, '\0', sizeof(vtable));

  for (instr = blk->begin; instr != blk->end->next; instr = instr->next) {
    // Update the general-purpose version table if necessary
    smt_update_vtable(instr, vtable);

    // Check if the access is relevant and, in the positive case,
    // create an access entry
    if (smt_is_relevant(instr)) {
      hnotice(3, "Checking whether '%s' at <%#08llx> has an equivalent...\n",
        instr->i.x86.mnemonic, instr->orig_addr);
      smt_resolve_access(blk, instr, vtable);
    }
  }
}

static size_t smt_trace_func(function *func, symbol *callfunc) {
  block *blk;
  smt_data *smt;

  size_t count;

  insn_info *instr;
  smt_access *access, *temp;

  // PHASE 1: INSTRUMENTATION
  // ------------------------
  // Relevant accesses are collected, the set of candidate
  // instructions is derived, access scores are computed
  // and some relevant accesses are eventually filtered
  // out of instrumentation depending on the user-defined
  // accuracy value

  // Total number of instrumented accesses for this function
  count = 0;

  for (blk = func->begin_blk; blk != func->end_blk->next; blk = blk->next) {
    smt = blk->smtracer;

    if (smt->score >= blk_score_threshold) {
      // The block will be instrumented because its assigned score is
      // greater than the acceptance blk_score_threshold
      hnotice(3, "Instrumenting block #%u with score %f\n", blk->id, smt->score);

      // Relevant accesses are collected and the set of
      // candidate instructions is derived
      smt_trace_block(blk);

      // Access scores are computed for all relevant accesses
      smt_compute_access_scores(blk);

      // A subset of relevant accesses is actually instrumented
      // according to the requested accuracy factor
      count += smt_instrument_block(blk);

      // Free unnecessary heap memory
      for (access = smt->candidates; access; access = temp) {
        temp = access->next;
        free(access);
      }
    }

  }

  // PHASE 2: FLUSHING
  // -----------------
  // Instrumented accesses which were temporarily stored into
  // the TLS buffer are passed to an external user-defined
  // function which consumes them; the point in the code
  // in which calls to this function are placed are referred
  // to as `flushpoints`

  for (instr = func->begin_insn; instr; instr = instr->next) {

    if (smt_is_flushpoint(instr, func)) {
      hnotice(3, "Found flushpoint '%s' at <%#08llx>\n",
        instr->i.x86.mnemonic, instr->orig_addr);

      if (count > 0) {
        // The user-defined routine is called with the base address of
        // the application-level buffer and the total number of
        // distinct accesses detected in this function
        smt_call_routine(count, callfunc, instr);
      }
    }
  }

  return count;
}

size_t smt_run(char *name, param **params, size_t numparams) {
  section *sec, *text;

  symbol *callfunc;
  function *func;

  size_t count, func_count;

  if (numparams > 4) {
    hinternal();
  }

  // We expect the params to be passed in the appropriate order
  blk_score_threshold = atof(params[0]->value);
  chunk_size = 1 << (atoi(params[1]->value));
  acc_threshold = atof(params[2]->value);
  use_stack = (numparams == 4) && !strcmp(params[3]->value, "true");

  // A weak symbol is created that represents the user-defined function
  for (text = NULL, sec = PROGRAM(sections)[PROGRAM(version)]; sec; sec = sec->next) {
    if (sec->type == SECTION_CODE) {
      text = sec;
      break;
    }
  }

  if (text == NULL) {
    hinternal();
  }

  callfunc = symbol_create(name, SYMBOL_UNDEF, SYMBOL_GLOBAL, text, 0);

  // We now iterate on all basic blocks to instrument the appropriate accesses
  count = 0;

  for (func = PROGRAM(v_code)[PROGRAM(version)]; func; func = func->next) {

    func_count = smt_trace_func(func, callfunc);
    count += func_count;

    // If it is a leaf function and it has to be instrumented,
    // we protect the stack in order to prevent errors resulting
    // from the infamous 😈 Red Area 😈

    if (func_count > 0 && ll_empty(&func->callto)) {
      // Protect the stack
      // -----------------
      // SUB $0x80, %rsp

      unsigned char instr[7] = {
        0x48, 0x81, 0xec, 0x80, 0x00, 0x00, 0x00
      };

      insert_instructions_at(func->begin_blk->end, instr, sizeof(instr),
        INSERT_AFTER, NULL);
    }

    if (func_count > 0 && ll_empty(&func->callto)) {
      // Unprotect the stack
      // -------------------
      // ADD $0x80, %rsp

      unsigned char instr[7] = {
        0x48, 0x81, 0xc4, 0x80, 0x00, 0x00, 0x00
      };

      insert_instructions_at(func->end_blk->begin, instr, sizeof(instr),
        INSERT_BEFORE, NULL);
    }

  }

  return count;
}
