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
#define BUFFER_MAX_SIZE   (1<<6)
#define BUFFER_NAME_LEN   (1<<5)



typedef struct vpage {
  unsigned long long counter;

  symbol *sym;
  block *blk;
  insn_info *pivot;

  struct vpage *next;
} vpage;


static section *tbss;
static symbol *tbss_sym, *tls_buffer;

static float threshold;
static size_t vpagesize;



inline static void vpt_tls_init() {
  section *sec;
  void *tbss_payload;
  unsigned int tbss_size;
  char *tbss_name;

  unsigned int count, disp;

  char *buffer_name;

  Section_Hdr *hdr;
  Elf64_Shdr *hdr64;
  Elf32_Shdr *hdr32;

  tbss_size = BUFFER_ENTRY_SIZE * BUFFER_MAX_SIZE;
  disp = 0;

  // Counting the total number of sections and looking for .tbss, if exists
  for (sec = PROGRAM(sections), count = 0; sec; sec = sec->next, ++count) {
    if (tbss == NULL && sec->name && !strcmp((const char *)sec->name, ".tbss")) {
      tbss = sec;
    }
    else if (tbss == NULL && sec->index && !strcmp((const char *) sec_name(sec->index), ".tbss")) {
      tbss = sec;
    }
  }

  if (tbss == NULL) {
    // If the section hasn't been found, it's time to create it
    hnotice(3, "Creating a new .tbss section\n");

    tbss_payload = calloc(tbss_size, 1);

    tbss = add_section(SECTION_TLS, count, tbss_payload, NULL);
    tbss_sym = create_symbol_node(".tbss", SYMBOL_SECTION, SYMBOL_LOCAL, 0);

    // Now the ELF header...
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

    tbss->header = hdr;

  } else {
    // Otherwise, let's hook to the existing section
    tbss_sym = find_symbol(".tbss");

    hnotice(3, "Existing .tbss section found of size %u bytes\n", tbss_sym->size);

    tbss_size += tbss_sym->size;
    tbss_payload = calloc(tbss_size, 1);

    hdr = tbss->header;

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

  tbss->payload = tbss->ptr = tbss_payload;
  tbss->name = ".tbss";

  tbss_sym->size = tbss_size;
  tbss_sym->sec = tbss;

  // A different buffer symbol is created for each version
  buffer_name = malloc(BUFFER_NAME_LEN);
  strcpy(buffer_name, "__vptracker_buffer_");
  sprintf(buffer_name + strlen("__vptracker_buffer_"), "%d", PROGRAM(version));

  tls_buffer = create_symbol_node(buffer_name, SYMBOL_TLS, SYMBOL_LOCAL,
    BUFFER_ENTRY_SIZE * BUFFER_MAX_SIZE);

  tls_buffer->sec = tbss;
  tls_buffer->position = disp;
  tls_buffer->secnum = tbss->index;
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
  ll_node *caller, *called;

  // First step: collect loop headers
  hnotice(3, "Collecting loop headers...\n");

  ll_init(&headers);

  for (func = PROGRAM(code); func; func = func->next) {
    graph_visit visit = {
      .payload   = &headers,
      .policy    = VISIT_DEPTH,
      .dir       = VISIT_FORWARD,
      .pre_func  = vpt_collect_loop_headers,
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
      .pre_func  = vpt_discover_loop_body,
      .post_func = NULL
    };

    block_graph_visit(&edge, &visit);
  }

  // Third step: compute the number of cycles a block participates to
  hnotice(3, "Computing cycles feature...\n");

  for (blk = PROGRAM(blocks)[PROGRAM(version)]; blk; blk = blk->next) {
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

    hnotice(6, "Block #%u participates to %u cycles...\n", blk->id, vptdata->cycles);
  }

  // Fourth step: ride CALL instructions to see if some blocks actually
  // participate to a higher number of cycles across function calls
  hnotice(3, "Extending cycle feature to block across different functions...\n");

  unsigned int hottest;
  linked_list queue = { NULL, NULL };

  for (func = PROGRAM(code); func; func = func->next) {
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
      vptdata = blk->vptracker;

      hnotice(3, "Caller block #%u for function '%s' participates to %u cycles\n",
        blk->id, func->name, vptdata->cycles);

      if (hottest < vptdata->cycles) {
        hottest = vptdata->cycles;
      }
    }

    hnotice(3, "Cycle feature will be extended by %u in func '%s'\n", hottest, func->name);

    for (blk = func->begin_blk; blk != func->end_blk->next; blk = blk->next) {
      vptdata = blk->vptracker;

      vptdata->cycles += hottest;
    }

    for (called = func->callto.first; called; called = called->next) {
      ll_push(&queue, called->elem);
    }
  }

  for (func = PROGRAM(code); func; func = func->next) {
    func->visited = false;
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

    if (highest == 0) {
      vptdata->score = 1.0;
    }
    else {
      vptdata->score /= highest;
    }

    blk = blk->next;
  }
}

void vpt_init(void) {
  block *blk;

  // Blocks are augmented with extra information for the duration of this
  // preset
  for (blk = PROGRAM(blocks)[PROGRAM(version)]; blk; blk = blk->next) {
    hnotice(6, "Allocating memory for vptracker at block #%u\n", blk->id);

    blk->vptracker = calloc(sizeof(block_vpt_data), 1);
  }

  // The application's IBR is augmented with TLS-enabling sections and symbols
  // that allow the instrumented logic to store data into the application's
  // address space
  vpt_tls_init();

  // Block-level features are computed to later instrument basic blocks according
  // to user-defined thresholds
  vpt_compute_score();
}

static void vpt_resolve_vpage(block *blk, insn_info *pivot, vpage **list) {
  insn_info_x86 *target_x86, *current_x86;

  vpage *target, *current, *prev, *found;
  section *target_sec, *current_sec;

  // A new virtual page is created to allow comparison with other
  // previously met virtual pages
  target = calloc(sizeof(vpage), 1);

  target->blk = blk;
  target->pivot = pivot;

  if (pivot->reference != NULL) {
    target->sym = pivot->reference;
  }

  if (target->sym) {
    target_sec = find_section(target->sym->secnum);
  }

  target_x86 = &pivot->i.x86;

  // We now scan the entire list of captured virtual pages to see if there's
  // a duplicate, in which case the new virtual page gets discarded
  current = *list;
  found = prev = NULL;

  while (current) {

    if (current->blk == blk) {
      current_x86 = &current->pivot->i.x86;

      // TODO: Verificare che i criteri sin qui espressi siano adeguati
      if (target->sym && current->sym) {
        current_sec = find_section(current->sym->secnum);

        if (target_sec == current_sec) {
          if ( abs(current->sym->position - target->sym->position) < vpagesize ) {
            hnotice(3, "Found by section correspondence\n");
            found = current;
            break;
          }
        }
      }

      else {
        if (target_x86->has_base_register && current_x86->has_base_register) {
          if (target_x86->breg == current_x86->breg
              && abs(target_x86->disp - current_x86->disp) < vpagesize ) {
            hnotice(3, "Found by base register correspondence\n");
            found = current;
            break;
          }
        }
        // else if (!target_x86->has_base_register && !current_x86->has_base_register) {
        //   if ( abs(target_x86->disp - current_x86->disp) < vpagesize ) {
        //     found = current;
        //     break;
        //   }
        // }
      }

    }

    prev = current;
    current = current->next;
  }

  if (found) {

    // If the page has been already instrumented, skip this access and only
    // increment the counter...
    hnotice(3, "Virtual page already found, incrementing counter...\n");

    found->counter += 1;

    free(target);

  } else {

    // We captured a new page, gotcha! It will be later stored into the
    // application's address space
    hnotice(3, "New virtual page found!\n");

    target->counter = 1;

    if (*list == NULL) {
      *list = target;
    } else {
      prev->next = target;
    }

  }
}

static void vpt_resolve_addr(vpage *entry) {
  insn_info *pivot, *current;
  insn_info_x86 *x86;
  symbol *sym, *ref;

  pivot = entry->pivot;
  x86 = &pivot->i.x86;
  sym = entry->sym;

  bool has_disp, has_fs;
  unsigned char scale, modrm, sib;

  hnotice(3, "Resolving address of memory reference in '%s' at <%#08llx> with %u + (%u + %u * %u)\n",
    pivot->i.x86.mnemonic, pivot->orig_addr, x86->disp, x86->breg, x86->ireg, x86->scale);

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

  has_disp = true;
  has_fs = x86->insn[0] == 0x64;

  // We replace the source/destination register with %rsi
  modrm = x86->modrm & 0xc7 | 0x30;
  sib = x86->sib;

  if (modrm >= 0x40 && modrm <= 0x7f) {
    // disp8 gets replaced with disp32
    modrm += 0x40;
  }
  else if (modrm <= 0x3f) {
    // Neither disp8 nor disp32
    has_disp = false;
  }

  // if (x86->has_base_register == false) {

  //   if (x86->has_index_register == false && x86->has_scale == false) {
  //     // No SIB (no base, no index and no scale)
  //     modrm = 0x00;
  //     sib = 0x00;
  //   } else {
  //     // SIB = S*I + 0 (no base)
  //     modrm = 0xb4;
  //     sib = 0x05 + 0x40 * scale + 0x08 * x86->ireg;
  //   }

  // } else {

  //   if (x86->has_index_register == false && x86->has_scale == false) {
  //     // No SIB (no index and no scale)
  //     modrm = 0xb0 + x86->breg;
  //     sib = 0x00;
  //   } else {
  //     // SIB = S*I + B
  //     modrm = 0xb0 + x86->breg;
  //     sib = x86->breg + 0x40 * scale + 0x08 * x86->ireg;
  //   }

  // }

  // if (x86->modrm <= 0x3f) {
  //   // It means the MOD field is 00B
  //   modrm -= 0x80;
  // }

  if (sym == NULL) {
    // No relocation, therefore it's likely to be a heap access
    hnotice(3, "Instruction carries no relocation\n");

    if (has_disp == false) {

      if (sib != 0) {

        if (has_fs == true) {
          unsigned char instr[9] = {
            0x64, 0x48, 0x8b, modrm, sib, 0x00, 0x00, 0x00, 0x00
          };

          insert_instructions_at(pivot, instr, sizeof(instr), INSERT_BEFORE, NULL);
        } else {
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

      instruction_rela_node(sym, current, RELOCATE_RELATIVE_32);
    }

    else if (sym->relocation.type == R_X86_64_32) {
      unsigned char instr[7] = {
        0x48, 0xc7, 0xc6, 0x00, 0x00, 0x00, 0x00
      };

      insert_instructions_at(pivot, instr, sizeof(instr), INSERT_BEFORE, &current);

      instruction_rela_node(sym, current, RELOCATE_ABSOLUTE_32);
    }

    else if (sym->relocation.type == R_X86_64_64) {
      unsigned char instr[10] = {
        0x48, 0xbe, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
      };

      insert_instructions_at(pivot, instr, sizeof(instr), INSERT_BEFORE, &current);

      instruction_rela_node(sym, current, RELOCATE_ABSOLUTE_64);
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

      ref = instruction_rela_node(sym, current, RELOCATE_TLS_RELATIVE_32);
      ref->relocation.addend = sym->relocation.addend;
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

      // instruction_rela_node(sym, current, RELOCATE_ABSOLUTE_64);
    }

  }
}

static void vpt_instrument_access(vpage *entry, unsigned int index) {
  insn_info *pivot, *current, *first;
  symbol *sym;

  pivot = entry->pivot;
  current = first = NULL;

  // Protect old register values
  // ---------------------------
  // PUSH %rsi

  {
    unsigned char instr[1] = {
      0x56
    };

    insert_instructions_at(pivot, instr, sizeof(instr), INSERT_BEFORE, &first);

    // If the instrumented instruction is the target of a jump, let's update
    // the virtual reference
    if (pivot == block_find(pivot)->begin && !pivot->virtual) {
      set_virtual_reference(pivot, first);
    }
  }

  // Resolve memory address
  // ----------------------
  // LEA disp(base, idx, scale), %rsi
  // MOV addr, %rsi
  // MOVABS addr, %rsi

  vpt_resolve_addr(entry);

  // Compute vpage address from memory address
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

  // Store vpage address in TLS buffer
  // ---------------------------------
  // MOV %rsi, %fs:disp+index*BUFFER_ENTRY_SIZE

  {
    unsigned char instr[9] = {
      0x64, 0x48, 0x89, 0x34, 0x25, 0x00, 0x00, 0x00, 0x00
    };

    insert_instructions_at(pivot, instr, sizeof(instr), INSERT_BEFORE, &current);

    sym = instruction_rela_node(tls_buffer, current, RELOCATE_TLS_RELATIVE_32);
    sym->relocation.offset = sym->relocation.addend;
    sym->relocation.addend = index * BUFFER_ENTRY_SIZE;
  }

  // Store vpage counter in TLS buffer
  // ---------------------------------
  // MOVQ entry->counter, %fs:disp+index*BUFFER_ENTRY_SIZE+BUFFER_ENTRY_SIZE/2

  if (index == 0) {
    unsigned char instr[13] = {
      0x64, 0x48, 0xc7, 0x04, 0x25,
      0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00
    };

    *(uint32_t *)(instr + 9) = entry->counter;

    insert_instructions_at(pivot, instr, sizeof(instr), INSERT_BEFORE, &current);

    sym = instruction_rela_node(tls_buffer, current, RELOCATE_TLS_RELATIVE_32);
    sym->relocation.offset = sym->relocation.addend;
    sym->relocation.addend = index * BUFFER_ENTRY_SIZE + BUFFER_ENTRY_SIZE / 2;
  }

  // Increment vpage counter in TLS buffer
  // -------------------------------------
  // MOVQ entry->counter, %rsi
  // ADD %rsi, %fs:disp+index*BUFFER_ENTRY_SIZE+BUFFER_ENTRY_SIZE/2

  else {

    {
      unsigned char instr[7] = {
        0x48, 0xc7, 0xc6, 0x00, 0x00, 0x00, 0x00
      };

      *(uint32_t *)(instr + 3) = entry->counter;

      insert_instructions_at(pivot, instr, sizeof(instr), INSERT_BEFORE, &current);
    }

    {
      unsigned char instr[9] = {
        0x64, 0x48, 0x01, 0x34, 0x25, 0x00, 0x00, 0x00, 0x00
      };

      insert_instructions_at(pivot, instr, sizeof(instr), INSERT_BEFORE, &current);

      sym = instruction_rela_node(tls_buffer, current, RELOCATE_TLS_RELATIVE_32);
      sym->relocation.offset = sym->relocation.addend;
      sym->relocation.addend = index * BUFFER_ENTRY_SIZE + BUFFER_ENTRY_SIZE / 2;
    }

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

static void vpt_call_routine(unsigned int total, symbol *callfunc, insn_info *pivot) {
  insn_info *current;
  symbol *sym;

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
    unsigned char instr[3] = {
      0x50,
      0x56,
      0x57
    };

    // unsigned char instr[86] = {
    //   0x9c,
    //   0x50,
    //   0x51,
    //   0x52,
    //   0x56,
    //   0x57,
    //   0x41, 0x50,
    //   0x41, 0x51,
    //   0x41, 0x52,
    //   0x41, 0x53,
    //   0x48, 0x83, 0xec, 0x10,
    //   0xf2, 0x0f, 0x11, 0x04, 0x24,
    //   0x48, 0x83, 0xec, 0x10,
    //   0xf2, 0x0f, 0x11, 0x0c, 0x24,
    //   0x48, 0x83, 0xec, 0x10,
    //   0xf2, 0x0f, 0x11, 0x14, 0x24,
    //   0x48, 0x83, 0xec, 0x10,
    //   0xf2, 0x0f, 0x11, 0x1c, 0x24,
    //   0x48, 0x83, 0xec, 0x10,
    //   0xf2, 0x0f, 0x11, 0x24, 0x24,
    //   0x48, 0x83, 0xec, 0x10,
    //   0xf2, 0x0f, 0x11, 0x2c, 0x24,
    //   0x48, 0x83, 0xec, 0x10,
    //   0xf2, 0x0f, 0x11, 0x34, 0x24,
    //   0x48, 0x83, 0xec, 0x10,
    //   0xf2, 0x0f, 0x11, 0x3c, 0x24
    // };

    insert_instructions_at(pivot->prev, instr, sizeof(instr), INSERT_AFTER, &current);
  }

  // Load TLS storage
  // ----------------
  // MOV %fs:0x0, %rdi

  {
    unsigned char instr[9] = {
      0x64, 0x48, 0x8b, 0x3c, 0x25, 0x00, 0x00, 0x00, 0x00
    };

    insert_instructions_at(current, instr, sizeof(instr), INSERT_AFTER, &current);
  }

  // Displace to TLS buffer
  // ----------------------
  // LEA disp(%rdi), %rdi

  {
    unsigned char instr[7] = {
      0x48, 0x8d, 0xbf, 0x00, 0x00, 0x00, 0x00
    };

    insert_instructions_at(current, instr, sizeof(instr), INSERT_AFTER, &current);

    instruction_rela_node(tls_buffer, current, RELOCATE_TLS_RELATIVE_32);
  }

  // Store total number of tracked vpages
  // ------------------------------------
  // MOV total, %rsi

  {
    unsigned char instr[7] = {
      0x48, 0xc7, 0xc6, 0x00, 0x00, 0x00, 0x00
    };

    *(uint32_t *)(instr + 3) = total;

    insert_instructions_at(current, instr, sizeof(instr), INSERT_AFTER, &current);
  }

  // Store user-defined routine address
  // ----------------------------------
  // MOV routine, %rax

  // {
  //   unsigned char instr[10] = {
  //     0x48, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
  //   };

  //   insert_instructions_at(current, instr, sizeof(instr), INSERT_AFTER, &current);

  //   instruction_rela_node(callfunc, current, RELOCATE_ABSOLUTE_64);
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

    insert_instructions_at(current, instr, sizeof(instr), INSERT_AFTER, &current);

    instruction_rela_node(callfunc, current, RELOCATE_RELATIVE_32);
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
    unsigned char instr[3] = {
      0x5f,
      0x5e,
      0x58
    };

    // unsigned char instr[86] = {
    //   0xf2, 0x0f, 0x10, 0x3c, 0x24,
    //   0x48, 0x83, 0xc4, 0x10,
    //   0xf2, 0x0f, 0x10, 0x34, 0x24,
    //   0x48, 0x83, 0xc4, 0x10,
    //   0xf2, 0x0f, 0x10, 0x2c, 0x24,
    //   0x48, 0x83, 0xc4, 0x10,
    //   0xf2, 0x0f, 0x10, 0x24, 0x24,
    //   0x48, 0x83, 0xc4, 0x10,
    //   0xf2, 0x0f, 0x10, 0x1c, 0x24,
    //   0x48, 0x83, 0xc4, 0x10,
    //   0xf2, 0x0f, 0x10, 0x14, 0x24,
    //   0x48, 0x83, 0xc4, 0x10,
    //   0xf2, 0x0f, 0x10, 0x0c, 0x24,
    //   0x48, 0x83, 0xc4, 0x10,
    //   0xf2, 0x0f, 0x10, 0x04, 0x24,
    //   0x48, 0x83, 0xc4, 0x10,
    //   0x41, 0x5b,
    //   0x41, 0x5a,
    //   0x41, 0x59,
    //   0x41, 0x58,
    //   0x5f,
    //   0x5e,
    //   0x5a,
    //   0x59,
    //   0x58,
    //   0x9d
    // };

    insert_instructions_at(current, instr, sizeof(instr), INSERT_AFTER, NULL);
  }
}

static void vpt_flush(vpage *first, symbol *callfunc, insn_info *flushpoint) {
  size_t index;

  vpage *entry;

  for (entry = first, index = 0; entry; entry = entry->next, ++index) {
    if (index < BUFFER_MAX_SIZE) {
      // If more pages are accessed than the expected number BUFFER_MAX_SIZE,
      // they will be skipped...

      // The virtual page address is resolved in the application's logic
      // by means of appropriate instrumentation code, and the final
      // access counter for that page is stored too into the application's
      // address space
      vpt_instrument_access(entry, index);
    }
  }

  if (index > 0) {
    // The user-defined routine is called accepting the base address of
    // the application-level buffer and the total number of different pages
    // detected in this basic block
    vpt_call_routine(index, callfunc, flushpoint);
  }

}

static size_t vpt_track_func(function *func, symbol *callfunc) {
  vpage *first, *entry, *prev;
  insn_info *pivot;
  block *blk;
  block_vpt_data *vptdata;
  symbol *sym;

  size_t count;

  first = NULL;
  pivot = NULL;
  count = 0;

  // Instrumentation phase
  for (blk = func->begin_blk; blk != func->end_blk->next; blk = blk->next) {
    vptdata = blk->vptracker;

    if (vptdata->score >= threshold) {
      // The block will be instrumented because its assigned score is
      // greater than the acceptance threshold
      hnotice(3, "Instrumenting block #%u with score %f\n", blk->id, vptdata->score);

      for (pivot = blk->begin; pivot != blk->end->next; pivot = pivot->next) {
        sym = pivot->reference;

        if (IS_MEMRD(pivot) || IS_MEMWR(pivot) || IS_MEMIND(pivot)
          || (sym && sym->type == SYMBOL_VARIABLE) || (sym && sym->type == SYMBOL_TLS)) {
          hnotice(3, "Checking relevant instruction '%s' at <%#08llx>\n",
            pivot->i.x86.mnemonic, pivot->orig_addr);

          vpt_resolve_vpage(blk, pivot, &first);

          ++count;
        }

      }
    }

  }

  // Flushing phase
  for (pivot = func->insn; pivot; pivot = pivot->next) {
    sym = pivot->reference;

    if ( (IS_CALL(pivot) && (pivot->jumpto || pivot->jumptable.size > 0 ))
         || pivot == func->end_blk->begin) {
      hnotice(3, "Found flushpoint at '%s' at <%#08llx>\n",
        pivot->i.x86.mnemonic, pivot->orig_addr);

      vpt_flush(first, callfunc, pivot);
    }
  }

  // Let's deallocate memory...
  entry = first;

  while (entry) {
    prev = entry;
    entry = entry->next;

    free(prev);
  }

  return count;
}

size_t vpt_track(char *name, param **params, size_t numparams) {
  symbol *callfunc;
  function *func;

  size_t count;

  if (numparams > 2) {
    hinternal();
  }

  // We expect the only params to be the threshold value and the exponent for
  // the virtual page size
  threshold = atof(params[0]->value);
  vpagesize = 1 << (atoi(params[1]->value));

  // A weak symbol is created that represents the user-defined function
  callfunc = create_symbol_node(name, SYMBOL_UNDEF, SYMBOL_GLOBAL, 0);

  // We now iterate on all basic blocks to instrument the appropriate accesses
  count = 0;

  for (func = PROGRAM(v_code)[PROGRAM(version)]; func; func = func->next) {

    if (ll_empty(&func->callto)) {
      // Protect the stack
      // -----------------
      // SUB $0x80, %rsp

      unsigned char instr[7] = {
        0x48, 0x81, 0xec, 0x80, 0x00, 0x00, 0x00
      };

      insert_instructions_at(func->begin_blk->end, instr, sizeof(instr), INSERT_AFTER, NULL);
    }

    count += vpt_track_func(func, callfunc);

    if (ll_empty(&func->callto)) {
      // Protect the stack
      // -----------------
      // ADD $0x80, %rsp

      unsigned char instr[7] = {
        0x48, 0x81, 0xc4, 0x80, 0x00, 0x00, 0x00
      };

      insert_instructions_at(func->end_blk->begin, instr, sizeof(instr), INSERT_BEFORE, NULL);
    }

  }

  return count;
}
