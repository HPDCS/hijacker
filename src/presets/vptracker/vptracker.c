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
* @file vptracker.c
* @brief Estimates the number of accesses to different virtual pages
* @author Simone Economo
*/

#include <stdint.h>
#include <string.h>

#include <hijacker.h>
#include <prints.h>
#include <ibr.h>

#include <elf/elf-defs.h>
#include <elf/handle-elf.h>

#include <vptracker/vptracker.h>

#define BUFFER_ENTRY_SIZE (1<<4)
#define BUFFER_MAX_SIZE       (1<<5)
#define VPAGE_SIZE        (1<<4) // TODO: In realtà andrebbe letto dal kernel
#define BUFFER_NAME_LEN   (1<<5)



typedef struct vpage {
  bool rip;

  unsigned char base;
  unsigned char index;
  unsigned char scale;

  symbol *sym;
  unsigned long disp;

  unsigned long counter;
  struct vpage *next;
} vpage;



static symbol *tls_buffer;



inline static void vpt_tls_init() {
  section *sec, *tbss;
  unsigned int count;

  char *buffer_name;

  Section_Hdr *hdr;
  Elf64_Shdr *hdr64;
  Elf32_Shdr *hdr32;

  sec = PROGRAM(sections);
  tbss = NULL;
  count = 0;

  while (sec) {
    if (sec->name && !strcmp((const char *)sec->name, ".tbss")) {
      tbss = sec;
      // break;
    }
    else if (sec->index && !strcmp((const char *) sec_name(sec->index), ".tbss")) {
      tbss = sec;
      // break;
    }
    sec = sec->next;
    ++count;
  }

  if (tbss == NULL) {
    // If the section hasn't been found, it's time to create it
    tbss = add_section(SECTION_RAW, count, NULL, NULL);
    tbss->name = ".tbss";

    // The respective symbol section must be created, too
    create_symbol_node(".tbss", SYMBOL_SECTION, SYMBOL_LOCAL, 0);

    // Now the ELF header...
    hdr = calloc(sizeof(Section_Hdr), 1);

    if (ELF(is64)) {
      hdr64 = &(hdr->section64);

      // hdr64->sh_name = elf_write_string(shstrtab, ".tbss");
      hdr64->sh_type = SHT_NOBITS;
      hdr64->sh_flags = SHF_WRITE | SHF_ALLOC | SHF_TLS;
      hdr64->sh_link = SHN_UNDEF;
      hdr64->sh_addralign = BUFFER_ENTRY_SIZE;
      hdr64->sh_size = BUFFER_ENTRY_SIZE * BUFFER_MAX_SIZE;
    } else {
      hdr32 = &(hdr->section32);

      // hdr32->sh_name = elf_write_string(shstrtab, ".tbss");
      hdr32->sh_type = SHT_NOBITS;
      hdr32->sh_flags = SHF_WRITE | SHF_ALLOC | SHF_TLS;
      hdr32->sh_link = SHN_UNDEF;
      hdr32->sh_addralign = BUFFER_ENTRY_SIZE;
      hdr32->sh_size = BUFFER_ENTRY_SIZE * BUFFER_MAX_SIZE;
    }

  } else {
    // Otherwise, let's hook to the existing section
    tbss->name = ".tbss";
    hdr = tbss->header;

    if (ELF(is64)) {
      hdr64 = &(hdr->section64);

      hdr64->sh_size += BUFFER_ENTRY_SIZE * BUFFER_MAX_SIZE;
    } else {
      hdr32 = &(hdr->section32);

      hdr32->sh_size += BUFFER_ENTRY_SIZE * BUFFER_MAX_SIZE;
    }
  }

  // A different buffer symbol is created for each version
  buffer_name = malloc(BUFFER_NAME_LEN);
  strcpy(buffer_name, "__vptracker_buffer_");
  sprintf(buffer_name + strlen("__vptracker_buffer_"), "%d", PROGRAM(version));

  tls_buffer = create_symbol_node(buffer_name, SYMBOL_TLS, SYMBOL_GLOBAL,
    BUFFER_ENTRY_SIZE * BUFFER_MAX_SIZE);

  tls_buffer->sec = tbss;
}

static bool vpt_collect_loop_headers(void *elem, void *data) {
  block_edge *edge = elem;
  linked_list *headers = data;

  if (edge->to->visited == false && edge->to->type == BLOCK_LOOP_HEADER) {
    ll_push(headers, edge->to);
  }

  return true;
}

static bool vpt_discover_loop_body(void *elem, void *data) {
  block_edge *edge = elem;
  block *header = data;

  block_vpt_data *vptdata;

  vptdata = edge->from->vptracker;

  // Stop the visit as soon as we're exiting the cycle
  if (edge->to == header && edge->dir == EDGE_NEXT) {
    return false;
  }

  // If the current block hasn't been visited yet, register its loop header
  if (edge->from->visited == false && edge->from != header) {
    vptdata->lheader = header;
  }

  // Do not enter inner loops, it will be done in a dedicated visit
  if (edge->from->type == BLOCK_LOOP_HEADER && edge->from != header) {
    return false;
  }

  return true;
}

inline static void vpt_compute_cycles() {
  linked_list headers;
  ll_node *source;
  block *blk, *header;
  block_vpt_data *vptdata;
  function *func;
  ll_node *caller;

  // First step: collect loop headers
  ll_init(&headers);

  func = PROGRAM(code);

  while (func) {
    graph_visit visit = {
      .payload   = &headers,
      .policy    = VISIT_DEPTH,
      .dir       = VISIT_FORWARD,
      .pre_func  = vpt_collect_loop_headers,
      .post_func = NULL
    };

    block_graph_visit(func->source->in.first->elem, &visit);

    func = func->next;
  }

  // Second step: discover loops body
  while (!ll_empty(&headers)) {
    header = ll_pop(&headers);

    block_edge edge = { EDGE_INIT, EDGE_NEXT, header, NULL };
    graph_visit visit = {
      .payload   = header,
      .policy    = VISIT_DEPTH,
      .dir       = VISIT_BACKWARD,
      .pre_func  = vpt_discover_loop_body,
      .post_func = NULL
    };

    block_graph_visit(&edge, &visit);
  }

  // Third step: compute the number of cycles a block participates to
  blk = PROGRAM(blocks)[PROGRAM(version)];

  while (blk) {
    vptdata = blk->vptracker;

    // A loop header participates in its own loop
    if (blk->type == BLOCK_LOOP_HEADER) {
      vptdata->cycles += 1;
    }

    header = vptdata->lheader;
    while (header) {
      vptdata->cycles += 1;
      header = ((block_vpt_data *)header->vptracker)->lheader;
    }

    blk = blk->next;
  }

  // Fourth step: ride CALL instructions to see if some blocks actually
  // participate to a higher number of cycles across function calls
  unsigned int hottest;

  func = PROGRAM(code);

  while (func) {
    hottest = 0;

    caller = func->calledfrom.first;
    while(caller) {
      blk = caller->elem;
      vptdata = blk->vptracker;

      if (hottest < vptdata->cycles) {
        hottest = vptdata->cycles;
      }
    }

    blk = func->begin_blk;
    while (blk != func->end_blk->next) {
      vptdata = blk->vptracker;

      vptdata->cycles += hottest;
      blk = blk->next;
    }

    func = func->next;
  }
}

inline static void vpt_compute_readratio() {
  // TODO: Non implementata
}

inline static void vpt_compute_hasvector() {
  // TODO: Non implementata
  return;
}

inline static void vpt_compute_score() {
  block *blk;
  block_vpt_data *vptdata;
  float highest;

  // Features are computed
  vpt_compute_cycles();

  vpt_compute_readratio();

  vpt_compute_hasvector();

  // The total absolute score is computed for each block
  blk = PROGRAM(blocks)[PROGRAM(version)];
  highest = 0;

  while (blk) {
    vptdata = blk->vptracker;

    vptdata->score = (
        vptdata->cycles
      + vptdata->readratio
      + vptdata->hasvector
    );

    if (highest < vptdata->score) {
      highest = vptdata->score;
    }

    blk = blk->next;
  }

  // The total relative score is computed based on the highest absolute one
  blk = PROGRAM(blocks)[PROGRAM(version)];

  while (blk) {
    vptdata = blk->vptracker;

    if (vptdata->score != highest) {
      vptdata->score /= highest;
    }

    blk = blk->next;
  }
}

void vpt_init(void) {
  block *blk;

  // Blocks are augmented with extra information for the duration of this
  // preset
  blk = PROGRAM(blocks)[PROGRAM(version)];

  while(blk) {
    blk->vptracker = calloc(sizeof(block_vpt_data), 1);

    blk = blk->next;
  }

  // The application's IBR is augmented with TLS-enabling sections and symbols
  // that allow the instrumented logic to store data into the application's
  // address space
  vpt_tls_init();

  // Block-level features are computed to later instrument basic blocks according
  // to user-defined thresholds
  vpt_compute_score();
}

static vpage *vpt_find_vpage(vpage *target, vpage *list) {
  vpage *entry;

  section *target_sec, *entry_sec;

  entry = list;

  if (target->sym) {
    target_sec = find_section(target->sym->secnum);
  }

  while (entry) {

    // TODO: Verificare che i criteri sin qui espressi siano adeguati
    if (target->sym && entry->sym) {
      entry_sec = find_section(entry->sym->secnum);

      if (target_sec == entry_sec) {
        if ( abs(entry->sym->position - target->sym->position) < VPAGE_SIZE ) {
          return entry;
        }
      }
    }

    else {
      if (target->base == entry->base) {
        if ( abs(target->disp - entry->disp) < VPAGE_SIZE ) {
          return entry;
        }
      }
    }

    entry = entry->next;
  }

  return NULL;
}

static void vpt_resolve_address(vpage *entry, unsigned int offset, insn_info *pivot) {
  insn_info *current;
  symbol *sym;

  current = NULL;

  // Protect old register values
  // ---------------------------
  // PUSH %rsi

  {
    unsigned char instr[1] = {
      0x56
    };

    insert_instructions_at(pivot, instr, sizeof(instr), INSERT_BEFORE, NULL);
  }

  // Resolve memory address
  // ----------------------
  // LEA disp(base, idx, scale), %rsi

  {
    unsigned char sib = entry->scale + entry->index << 3 + entry->base << 6;

    if (entry->sym == NULL) {
      // No relocation, therefore it's likely to be a heap access

      if (entry->disp == 0x0) {
        unsigned char instr[4] = {
          0x48, 0x8d, 0x34, sib
        };

        insert_instructions_at(pivot, instr, sizeof(instr), INSERT_BEFORE, NULL);
      }
      else {
        unsigned char instr[8] = {
          0x48, 0x8d, 0xb4, sib, 0x00, 0x00, 0x00, 0x00
        };

        *(uint32_t *)(instr + 4) = entry->disp;

        insert_instructions_at(pivot, instr, sizeof(instr), INSERT_BEFORE, NULL);
      }

    } else {

      if (entry->rip == true) {
        unsigned char instr[7] = {
          0x48, 0x8d, 0x35, 0x00, 0x00, 0x00, 0x00
        };

        insert_instructions_at(pivot, instr, sizeof(instr), INSERT_BEFORE, &current);
      }
      else {
        unsigned char instr[8] = {
          0x48, 0x8d, 0xb4, sib, 0x00, 0x00, 0x00, 0x00
        };

        insert_instructions_at(pivot, instr, sizeof(instr), INSERT_BEFORE, &current);
      }

      // We have a relocation, therefore we must reflect that with a new
      // relocation entry
      instruction_rela_node(entry->sym, current, RELOCATE_ABSOLUTE_32);

    }
  }

  // Compute vpage address from memory address
  // -----------------------------------------
  // SHR %rsi, $12

  {
    unsigned char instr[4] = {
      0x48, 0xc1, 0xee, 0x0c
    };

    insert_instructions_at(pivot, instr, sizeof(instr), INSERT_BEFORE, NULL);
  }

  // Store vpage address in TLS buffer
  // ---------------------------------
  // MOV %rsi, %fs:disp+offset*BUFFER_ENTRY_SIZE

  {
    unsigned char instr[9] = {
      0x64, 0x48, 0x89, 0x34, 0x25, 0x00, 0x00, 0x00, 0x00
    };

    insert_instructions_at(pivot, instr, sizeof(instr), INSERT_BEFORE, &current);

    sym = instruction_rela_node(tls_buffer, current, RELOCATE_TLS_RELATIVE_32);
    sym->relocation.offset = sym->relocation.addend;
    sym->relocation.addend = offset * BUFFER_ENTRY_SIZE;
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

static void vpt_store_counter(vpage *entry, unsigned int offset, insn_info *pivot) {
  insn_info *current;
  symbol *sym;

  current = NULL;

  // Store vpage counter in TLS buffer
  // ---------------------------------
  // MOV entry->counter, %fs:disp+offset*BUFFER_ENTRY_SIZE+BUFFER_ENTRY_SIZE/2(%rdi)

  {
    unsigned char instr[11] = {
      0x48, 0xc7, 0x87, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    };

    *(uint32_t *)(instr + 7) = entry->counter;

    insert_instructions_at(pivot, instr, sizeof(instr), INSERT_BEFORE, &current);

    sym = instruction_rela_node(tls_buffer, current, RELOCATE_TLS_RELATIVE_32);
    sym->relocation.offset = sym->relocation.addend;
    sym->relocation.addend = offset * BUFFER_ENTRY_SIZE + BUFFER_ENTRY_SIZE / 2;
  }

}

static void vpt_call_routine(unsigned int total, symbol *func, insn_info *pivot) {
  insn_info *current;
  symbol *sym;

  current = NULL;

  // Protect old register values
  // ---------------------------
  // PUSH %rsi
  // PUSH %rdi
  // PUSH %r8

  {
    unsigned char instr[4] = {
      0x56,
      0x57,
      0x41, 0x50
    };

    insert_instructions_at(pivot, instr, sizeof(instr), INSERT_BEFORE, NULL);
  }

  // Save caller-save registers
  // --------------------------
  // PUSH %rax
  // PUSH %rcx
  // PUSH %rdx
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
    unsigned char instr[81] = {
      0x50,
      0x51,
      0x52,
      0x41, 0x51,
      0x41, 0x52,
      0x41, 0x53,
      0x48, 0x83, 0xec, 0x10,
      0xf2, 0x0f, 0x11, 0x04, 0x24,
      0x48, 0x83, 0xec, 0x10,
      0xf2, 0x0f, 0x11, 0x0c, 0x24,
      0x48, 0x83, 0xec, 0x10,
      0xf2, 0x0f, 0x11, 0x14, 0x24,
      0x48, 0x83, 0xec, 0x10,
      0xf2, 0x0f, 0x11, 0x1c, 0x24,
      0x48, 0x83, 0xec, 0x10,
      0xf2, 0x0f, 0x11, 0x24, 0x24,
      0x48, 0x83, 0xec, 0x10,
      0xf2, 0x0f, 0x11, 0x2c, 0x24,
      0x48, 0x83, 0xec, 0x10,
      0xf2, 0x0f, 0x11, 0x34, 0x24,
      0x48, 0x83, 0xec, 0x10,
      0xf2, 0x0f, 0x11, 0x3c, 0x24
    };

    insert_instructions_at(pivot, instr, sizeof(instr), INSERT_BEFORE, NULL);
  }

  // Store total number of tracked vpages
  // ------------------------------------
  // MOV total, %rsi

  {
    unsigned char instr[7] = {
      0x48, 0xc7, 0xc6, 0x00, 0x00, 0x00, 0x00
    };

    insert_instructions_at(pivot, instr, sizeof(instr), INSERT_BEFORE, NULL);
  }

  // Load TLS buffer
  // ---------------
  // MOV %fs:disp, %rdi

  {
    unsigned char instr[9] = {
      0x64, 0x48, 0x8b, 0x3c, 0x25, 0x00, 0x00, 0x00, 0x00
    };

    insert_instructions_at(pivot, instr, sizeof(instr), INSERT_BEFORE, &current);

    instruction_rela_node(tls_buffer, current, RELOCATE_TLS_RELATIVE_32);
  }

  // Store user-defined routine address
  // ----------------------------------
  // MOV routine, %r8

  {
    unsigned char instr[10] = {
      0x49, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    };

    insert_instructions_at(pivot, instr, sizeof(instr), INSERT_BEFORE, &current);

    instruction_rela_node(func, current, RELOCATE_ABSOLUTE_64);
  }

  // Call user-defined routine
  // -------------------------
  // CALL *(%r8)

  {
    unsigned char instr[3] = {
      0x41, 0xff, 0x10
    };

    insert_instructions_at(pivot, instr, sizeof(instr), INSERT_BEFORE, NULL);
  }

  // Restore caller-save registers
  // -----------------------------
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
  // POP %rdx
  // POP %rcx
  // POP %rax

  {
    unsigned char instr[81] = {
      0xf2, 0x0f, 0x10, 0x3c, 0x24,
      0x48, 0x83, 0xc4, 0x10,
      0xf2, 0x0f, 0x10, 0x34, 0x24,
      0x48, 0x83, 0xc4, 0x10,
      0xf2, 0x0f, 0x10, 0x2c, 0x24,
      0x48, 0x83, 0xc4, 0x10,
      0xf2, 0x0f, 0x10, 0x24, 0x24,
      0x48, 0x83, 0xc4, 0x10,
      0xf2, 0x0f, 0x10, 0x1c, 0x24,
      0x48, 0x83, 0xc4, 0x10,
      0xf2, 0x0f, 0x10, 0x14, 0x24,
      0x48, 0x83, 0xc4, 0x10,
      0xf2, 0x0f, 0x10, 0x0c, 0x24,
      0x48, 0x83, 0xc4, 0x10,
      0xf2, 0x0f, 0x10, 0x04, 0x24,
      0x48, 0x83, 0xc4, 0x10,
      0x41, 0x5b,
      0x41, 0x5a,
      0x41, 0x59,
      0x5a,
      0x59,
      0x58
    };

    insert_instructions_at(pivot, instr, sizeof(instr), INSERT_BEFORE, NULL);
  }

  // Restore old register values
  // ---------------------------
  // POP %r8
  // POP %rdi
  // POP %rsi

  {
    unsigned char instr[4] = {
      0x41, 0x58,
      0x5f,
      0x5e
    };

    insert_instructions_at(pivot, instr, sizeof(instr), INSERT_BEFORE, NULL);
  }
}

static void vpt_instrument_access(insn_info *instr, unsigned int index, vpage **first, vpage **prev) {
  vpage *entry, *found;
  unsigned int offset;

  hnotice(3, "Instrumenting instruction '%s' at <%#08llx>\n",
    instr->i.x86.mnemonic, instr->orig_addr);

  entry = calloc(sizeof(vpage), 1);

  if (instr->i.x86.uses_rip) {
    entry->rip = true;
  } else {
    entry->base = instr->i.x86.breg;
    entry->index = instr->i.x86.ireg;
    entry->scale = instr->i.x86.scale;
    entry->disp = instr->i.x86.disp;
  }

  if (instr->reference != NULL) {
    entry->sym = instr->reference;
  }

  entry->counter = 1;

  // if (instr->x86.disp == 0x0 && instr->reference != NULL) {
  //   // We have a relocation, therefore we store the symbol offset
  //   // from the symbol's section as the displacement
  //   symbol *sym = instr->reference;

  //   entry->disp.section = sym->secnum;
  //   entry->disp.offset = sym->position;
  // } else {
  //   // No relocation in place, just store the raw displacement
  //   entry->disp.offset = instr->x86.disp;
  // }

  found = vpt_find_vpage(entry, *first);

  if (found) {
    hnotice(3, "Virtual page already found, incrementing counter...\n");
    // If the page has been already instrumented, skip this access and only
    // increment the counter
    free(entry);
    entry = NULL;

    ++found->counter;
  } else {
    hnotice(3, "New virtual page found!\n");
    // We captured a new page, let's store it into the application's address
    // space and insert the instrumented code

    if (index < BUFFER_MAX_SIZE) {
      // If more pages are accessed than the expected number BUFFER_MAX_SIZE,
      // they will be skipped
      offset = index * BUFFER_ENTRY_SIZE;

      // The virtual page address is resolved in the application's logic
      // by means of appropriate instrumentation code
      vpt_resolve_address(entry, offset, instr);
    }

    if (*prev != NULL) {
      (*prev)->next = entry;
      *prev = entry;
    } else {
      *first = entry;
    }
  }
}

size_t vpt_track(char *name, param **params, size_t numparams) {
  float threshold;
  symbol *func, *sym;

  block *block;
  block_vpt_data *vptdata;
  insn_info *instr;

  vpage *first, *entry, *prev;
  unsigned int count, index, total;

  if (numparams > 1) {
    hinternal();
  }

  // We expect the only param to be the threshold value, which is a float
  threshold = atof(params[0]->value);

  // A weak symbol is created that represents the user-defined function
  func = create_symbol_node(name, SYMBOL_UNDEF, SYMBOL_GLOBAL, 0);

  // We now iterate on all basic blocks to instrument the appropriate accesses
  block = PROGRAM(blocks)[PROGRAM(version)];
  first = entry = prev = NULL;
  count = 0;

  while (block) {
    vptdata = block->vptracker;
    index = 0;

    if (vptdata->score > threshold) {
      hnotice(3, "Instrumenting block #%u with score %f\n", block->id, vptdata->score);

      // The block will be instrumented because its assigned score is
      // greater than the acceptance threshold
      instr = block->begin;

      while (instr != block->end->next) {
        if (instr->flags & I_MEMRD) {
          vpt_instrument_access(instr, index, &first, &prev);
          ++index; ++count;
        }

        instr = instr->next;
      }

      // Let's make sure that we didn't forget other instructions
      // such as LEA which work with memory references through
      // relocation entries
      sym = PROGRAM(symbols);

      while (sym) {
        instr = sym->relocation.ref_insn;

        // We only look at those relocations that fall into the current
        // block. Note that this step is more expensive than needed and can
        // be probably optimized by improving the symbols lookup mechanism
        if (block_find(instr) == block) {

          // I_MEMRD instructions have already been instrumented...
          // ... I_MEMWR instructions need not be taken into account
          // since they always hit the cache!
          if (instr->flags & I_MEMRD == false && instr->flags & I_MEMWR == false) {
            vpt_instrument_access(instr, index, &first, &prev);
            ++index; ++count;
          }

        }

        sym = sym->next;
      }

      instr = block->end;
      entry = first;
      total = index;
      index = 0;

      while (entry) {
        // The final access counter for that page is stored into the application's
        // address space by means of appropriate instrumentation code
        vpt_store_counter(entry, index, instr);

        entry = entry->next;
        free(entry);

        ++index;
      }

      if (total > 0) {
        // The final user-defined routine is called accepting the base address
        // of the application-level buffer and the total number of different pages
        // detected in this basic block
        vpt_call_routine(total, func, instr);
      }
    }

    block = block->next;
  }

  return count;
}
