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

#include <presets/vptracker.h>

#define BUFFER_ENTRY_SIZE (1<<4)
#define BUFFER_SIZE       (1<<5)
#define VPAGE_SIZE        (1<<4) // TODO: In realtà andrebbe letto dal kernel

#define PRESET_NAME "vptracker"



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



inline static void vp_tls_init() {
  section *sec, *tbss;
  unsigned int count;

  Section_Hdr *hdr;
  Elf64_Shdr *hdr64;
  Elf32_Shdr *hdr32;

  sec = PROGRAM(sections);
  tbss = NULL;
  count = 0;

  while (sec) {
    if (!strcmp((const char *)sec->name, ".tbss")) {
      tbss = sec;
    }
    sec = sec->next;
    ++count;
  }

  if (tbss == NULL) {
    // If the section hasn't been found, it's time to create it
    tbss = add_section(SECTION_RAW, count, NULL, NULL);

    // The respective symbol section must be created, too
    create_symbol_node("", SYMBOL_SECTION, SYMBOL_LOCAL, 0);

    // Now the ELF header...
    hdr = calloc(sizeof(Section_Hdr), 1);

    // TODO: sh_addr non so cosa metterci, cribbio!
    if (ELF(is64)) {
      hdr64 = &(hdr->section64);

      // hdr64->sh_name = elf_write_string(shstrtab, ".tbss");
      hdr64->sh_type = SHT_NOBITS;
      hdr64->sh_flags = SHF_WRITE | SHF_ALLOC | SHF_TLS;
      hdr64->sh_link = SHN_UNDEF;
      hdr64->sh_addralign = BUFFER_ENTRY_SIZE;
      hdr64->sh_size = BUFFER_SIZE;
    } else {
      hdr32 = &(hdr->section32);

      // hdr32->sh_name = elf_write_string(shstrtab, ".tbss");
      hdr32->sh_type = SHT_NOBITS;
      hdr32->sh_flags = SHF_WRITE | SHF_ALLOC | SHF_TLS;
      hdr32->sh_link = SHN_UNDEF;
      hdr32->sh_addralign = BUFFER_ENTRY_SIZE;
      hdr32->sh_size = BUFFER_SIZE;
    }

  } else {
    // Otherwise, let's hook to the existing section
    hdr = tbss->header;

    if (ELF(is64)) {
      hdr64 = &(hdr->section64);

      hdr64->sh_size += BUFFER_ENTRY_SIZE;
    } else {
      hdr32 = &(hdr->section32);

      hdr32->sh_size += BUFFER_ENTRY_SIZE;
    }
  }

  create_symbol_node("__vptracker_buffer", SYMBOL_TLS, SYMBOL_GLOBAL, BUFFER_SIZE);
}

static bool vp_collect_loop_headers(void *elem, void *data) {
  block_edge *edge = elem;
  linked_list *headers = data;

  if (edge->to->visited == false && edge->to->type == BLOCK_LOOP_HEADER) {
    ll_push(headers, edge->to);
  }

  return true;
}

static bool vp_discover_loop_body(void *elem, void *data) {
  block_edge *edge = elem;
  block *header = data;

  block_vptracker_data *vptdata;

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

inline static void vp_compute_cycles() {
  linked_list headers;
  ll_node *source;
  block *blk, *header;
  block_vptracker_data *vptdata;

  // First visit: collect loop headers
  ll_init(&headers);

  {
    graph_visit visit = {
      .payload   = &headers,
      .policy    = VISIT_DEPTH,
      .dir       = VISIT_FORWARD,
      .pre_func  = vp_collect_loop_headers,
      .post_func = NULL
    };

    source = block_graph.sources.first;
    while (source) {
      blk = source->elem;
      block_graph_visit(blk->in.first->elem, &visit);

      source = source->next;
    }
  }

  // Second visit: increase cycle counter
  while (!ll_empty(&headers)) {
    header = ll_pop(&headers);

    block_edge edge = { EDGE_INIT, EDGE_NEXT, header, NULL };
    graph_visit visit = {
      .payload   = header,
      .policy    = VISIT_DEPTH,
      .dir       = VISIT_BACKWARD,
      .pre_func  = vp_discover_loop_body,
      .post_func = NULL
    };

    block_graph_visit(&edge, &visit);
  }

  // Compute the number of cycles a block participates to
  blk = PROGRAM(blocks);

  while (blk) {
    vptdata = blk->vptracker;

    // A loop header participates in its own loop
    if (blk->type == BLOCK_LOOP_HEADER) {
      vptdata->cycles += 1;
    }

    header = vptdata->lheader;
    while (header) {
      vptdata->cycles += 1;
      header = ((block_vptracker_data *)header->vptracker)->lheader;
    }

    blk = blk->next;
  }
}

inline static void vp_compute_readratio() {
  // TODO: Non implementata
}

inline static void vp_compute_hasvector() {
  // TODO: Non implementata
  return;
}

inline static void vp_compute_score() {
  block *blk;
  block_vptracker_data *vptdata;
  float highest;

  // Features are computed
  vp_compute_cycles();

  vp_compute_readratio();

  vp_compute_hasvector();

  // The total absolute score is computed for each block
  blk = PROGRAM(blocks);
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
  blk = PROGRAM(blocks);
  while (blk) {
    vptdata = blk->vptracker;

    if (vptdata->score != highest) {
      vptdata->score /= highest;
    }

    blk = blk->next;
  }
}

void vp_init() {
  block *blk;

  // Blocks are augmented with extra information for the duration of this
  // preset
  blk = PROGRAM(blocks);
  while(blk) {
    blk->vptracker = calloc(sizeof(block_vptracker_data), 1);

    blk = blk->next;
  }

  // The application's IBR is augmented with TLS-enabling sections and symbols
  // that allow the instrumented logic to store data into the application's
  // address space
  vp_tls_init();

  // Block-level features are computed to later instrument basic blocks according
  // to user-defined thresholds
  vp_compute_score();
}

static vpage *vp_find_vpage(vpage *target, vpage *list) {
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

static inline void vp_resolve_address(vpage *entry, unsigned int offset, insn_info *pivot) {

  // Protect old register values
  // ---------------------------
  // PUSH %rsi
  // PUSH %rdi

  {
    unsigned char instr[2] = {
      0x56,
      0x57
    };

    insert_instructions_at(pivot, instr, sizeof(instr), INSERT_BEFORE, &pivot);
  }

  // Resolve memory address
  // ----------------------
  // LEA disp(base, idx, scale), %rsi

  {
    unsigned char modrm;
    unsigned char sib;
    unsigned long disp;

    if (entry->rip) {
      modrm = 0x35;
      sib = 0x25;
    } else {
      modrm = 0x34;
      sib = entry->base + entry->index << 3 + entry->scale << 6;
    }

    if (entry->disp == 0x0 && entry->sym == NULL) {
      unsigned char instr[4] = {
        0x48, 0x8d, modrm, sib
      };

      insert_instructions_at(pivot, instr, sizeof(instr), INSERT_BEFORE, &pivot);
    } else {
      unsigned char instr[5] = {
        0x48, 0x8d, modrm, sib, entry->disp
      };

      insert_instructions_at(pivot, instr, sizeof(instr), INSERT_BEFORE, &pivot);

      if (entry->sym != NULL) {
        // We have a relocation, therefore we must reflect that with a new
        // relocation entry

        instruction_rela_node(entry->sym, pivot, RELOCATE_ABSOLUTE_32);
      }
    }
  }

  // Compute vpage address from memory address
  // -----------------------------------------
  // SHR %rsi, $12

  {
    unsigned char instr[4] = {
      0x48, 0xc1, 0xee, 0x0c
    };

    insert_instructions_at(pivot, instr, sizeof(instr), INSERT_BEFORE, &pivot);
  }

  // Load TLS buffer
  // ---------------
  // MOV %fs:disp, %rdi

  {
    unsigned char instr[9] = {
      0x64, 0x48, 0x8b, 0x3c, 0x25, 0x00, 0x00, 0x00, 0x00
    };

    insert_instructions_at(pivot, instr, sizeof(instr), INSERT_BEFORE, &pivot);

    instruction_rela_node(tls_buffer, pivot, RELOCATE_TLS_RELATIVE_32);
  }

  // Store vpage address in TLS buffer
  // ---------------------------------
  // MOV %rsi, offset*BUFFER_ENTRY_SIZE(%rdi)

  {
    unsigned char instr[4] = {
      0x48, 0x89, 0x77, offset * BUFFER_ENTRY_SIZE
    };

    insert_instructions_at(pivot, instr, sizeof(instr), INSERT_BEFORE, &pivot);
  }

  // Restore old register values
  // ---------------------------
  // POP %rdi
  // POP %rsi

  {
    unsigned char instr[2] = {
      0x5f,
      0x5e
    };

    insert_instructions_at(pivot, instr, sizeof(instr), INSERT_BEFORE, &pivot);
  }
}

static inline void vp_store_counter(vpage *entry, unsigned int offset, insn_info *pivot) {

  // Protect old register values
  // ---------------------------
  // PUSH %rdi

  {
    unsigned char instr[1] = {
      0x57
    };

    insert_instructions_at(pivot, instr, sizeof(instr), INSERT_BEFORE, &pivot);
  }

  // Load TLS buffer
  // ---------------
  // MOV %fs:disp, %rdi

  {
    unsigned char instr[9] = {
      0x64, 0x48, 0x8b, 0x3c, 0x25, 0x00, 0x00, 0x00, 0x00
    };

    insert_instructions_at(pivot, instr, sizeof(instr), INSERT_BEFORE, &pivot);

    instruction_rela_node(tls_buffer, pivot, RELOCATE_TLS_RELATIVE_32);
  }

  // Store vpage counter in TLS buffer
  // ---------------------------------
  // MOV entry->counter, offset*BUFFER_ENTRY_SIZE+BUFFER_ENTRY_SIZE/2(%rdi)

  {
    unsigned char instr[8] = {
      0x48, 0xc7, 0x47, 0x00, 0x00, 0x00, 0x00, 0x0c
    };

    *(uint32_t *)(instr + 3) = offset * BUFFER_ENTRY_SIZE + BUFFER_ENTRY_SIZE / 2;

    insert_instructions_at(pivot, instr, sizeof(instr), INSERT_BEFORE, &pivot);
  }

  // Restore old register values
  // ---------------------------
  // POP %rdi

  {
    unsigned char instr[2] = {
      0x5e
    };

    insert_instructions_at(pivot, instr, sizeof(instr), INSERT_BEFORE, &pivot);
  }
}

static inline void vp_call_routine(unsigned int total, symbol *func, insn_info *pivot) {

  // Protect old register values
  // ---------------------------
  // PUSH %rsi
  // PUSH %rdi

  {
    unsigned char instr[2] = {
      0x56,
      0x57
    };

    insert_instructions_at(pivot, instr, sizeof(instr), INSERT_BEFORE, &pivot);
  }

  // Store total number of tracked vpages
  // ------------------------------------
  // MOV total, %rsi

  {
    unsigned char instr[7] = {
      0x48, 0xc7, 0xc6, 0x00, 0x00, 0x00, 0x00
    };

    insert_instructions_at(pivot, instr, sizeof(instr), INSERT_BEFORE, &pivot);
  }

  // Load TLS buffer
  // ---------------
  // MOV %fs:disp, %rdi

  {
    unsigned char instr[9] = {
      0x64, 0x48, 0x8b, 0x3c, 0x25, 0x00, 0x00, 0x00, 0x00
    };

    insert_instructions_at(pivot, instr, sizeof(instr), INSERT_BEFORE, &pivot);

    instruction_rela_node(tls_buffer, pivot, RELOCATE_TLS_RELATIVE_32);
  }

  // Call user-defined routine
  // -------------------------
  // CALL routine

  {
    unsigned char instr[5] = {
      0xe8, 0x00, 0x00, 0x00, 0x00
    };

    insert_instructions_at(pivot, instr, sizeof(instr), INSERT_BEFORE, &pivot);

    instruction_rela_node(func, pivot, RELOCATE_RELATIVE_32);
  }

  // Restore old register values
  // ---------------------------
  // POP %rdi
  // POP %rsi

  {
    unsigned char instr[2] = {
      0x5f,
      0x5e
    };

    insert_instructions_at(pivot, instr, sizeof(instr), INSERT_BEFORE, &pivot);
  }
}

void vp_track(float threshold, unsigned char *func) {
  symbol *sym;
  block *block;
  block_vptracker_data *vptdata;
  insn_info *instr;
  vpage *first, *entry, *prev, *found;

  unsigned int index, offset, total;

  sym = find_symbol(func);

  if (sym == NULL || sym->type != SYMBOL_FUNCTION) {
    herror(true, "[%s] Invalid user-defined function provided", PRESET_NAME);
  }

  block = PROGRAM(blocks);
  index = 0;

  while (block) {
    vptdata = block->vptracker;

    if (vptdata->score > threshold) {
      // The block will be instrumented because its assigned score is
      // greater than the acceptance threshold
      instr = block->begin;

      while (instr) {
        // TODO: Tenere conto anche delle istruzioni LEA
        if (instr->flags & I_MEMRD) {
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

          found = vp_find_vpage(entry, first);

          if (found) {
            // If the page has been already instrumented, skip this access and only
            // increment the counter
            free(entry);
            entry = NULL;

            ++found->counter;
          } else {
            // We captured a new page, let's store it into the application's address
            // space and insert the instrumented code

            if (index < BUFFER_SIZE) {
              // If more pages are accessed than the expected number BUFFER_SIZE,
              // they will be skipped
              offset = index * BUFFER_ENTRY_SIZE;

              // The virtual page address is resolved in the application's logic
              // by means of appropriate instrumentation code
              vp_resolve_address(entry, offset, instr);
            }

            if (prev != NULL) {
              prev->next = entry;
              prev = entry;
            } else {
              first = entry;
            }
          }

        }
      }

      entry = first;
      offset = total = 0;

      while (entry) {
        // The final access counter for that page is stored into the application's
        // address space by means of appropriate instrumentation code
        vp_store_counter(entry, offset, instr);

        entry = entry->next;
        free(entry);

        ++offset;
        ++total;
      }

      if (total > 0) {
        // The final user-defined routine is called accepting the base address
        // of the application-level buffer and the total number of different pages
        // detected in this basic block
        vp_call_routine(total, sym, instr);
      }
    }

    block = block->next;
  }
}
