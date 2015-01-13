/*
 * internal execution defines for qemu
 *
 *  Copyright (c) 2003 Fabrice Bellard
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, see <http://www.gnu.org/licenses/>.
 */

#ifndef _EXEC_ALL_H_
#define _EXEC_ALL_H_

#include "qemu-common.h"
#include "exec/cpu-common.h"
#include "exec/cpu-all.h"

/* allow to see translation results - the slowdown should be negligible, so we leave it */
#define DEBUG_DISAS

/* Page tracking code uses ram addresses in system mode, and virtual
   addresses in userspace mode.  Define tb_page_addr_t to be an appropriate
   type.  */
#if defined(CONFIG_USER_ONLY)
typedef abi_ulong tb_page_addr_t;
#else
typedef ram_addr_t tb_page_addr_t;
#endif

/* is_jmp field values */
#define DISAS_NEXT    0 /* next instruction can be analyzed */
#define DISAS_JUMP    1 /* only pc was modified dynamically */
#define DISAS_UPDATE  2 /* cpu state was modified dynamically */
#define DISAS_TB_JUMP 3 /* only pc was modified statically */

struct TranslationBlock;
typedef struct TranslationBlock TranslationBlock;

/* XXX: make safe guess about sizes */
#define MAX_OP_PER_INSTR 208

/* A Call op needs up to 6 + 2N parameters (N = number of arguments).  */
#define MAX_OPC_PARAM 10
#define OPC_BUF_SIZE 2048
#define OPC_MAX_SIZE (OPC_BUF_SIZE - MAX_OP_PER_INSTR)

/* Maximum size a TCG op can expand to.  This is complicated because a
   single op may require several host instructions and register reloads.
   For now take a wild guess at 192 bytes, which should allow at least
   a couple of fixup instructions per argument.  */
#define TCG_MAX_OP_SIZE 192

#define OPPARAM_BUF_SIZE (OPC_BUF_SIZE * MAX_OPC_PARAM)

#include "qemu/log.h"

void gen_intermediate_code(CPUArchState *env, struct TranslationBlock *tb);
void gen_intermediate_code_pc(CPUArchState *env, struct TranslationBlock *tb);
void restore_state_to_opc(CPUArchState *env, struct TranslationBlock *tb,
                          int pc_pos);

unsigned long code_gen_max_block_size(void);
void cpu_gen_init(void);
void tcg_exec_init(unsigned long tb_size);
int cpu_gen_code(CPUArchState *env, struct TranslationBlock *tb,
                 int *gen_code_size_ptr);
bool cpu_restore_state(CPUArchState *env, uintptr_t searched_pc);

void QEMU_NORETURN cpu_resume_from_signal(CPUArchState *env1, void *puc);
void QEMU_NORETURN cpu_io_recompile(CPUArchState *env, uintptr_t retaddr);
TranslationBlock *tb_gen_code(CPUArchState *env, 
                              target_ulong pc, target_ulong cs_base, int flags,
                              int cflags);
void cpu_exec_init(CPUArchState *env);
void QEMU_NORETURN cpu_loop_exit(CPUArchState *env1);
int page_unprotect(target_ulong address, uintptr_t pc, void *puc);
void tb_invalidate_phys_page_range(tb_page_addr_t start, tb_page_addr_t end,
                                   int is_cpu_write_access);
void tb_invalidate_phys_range(tb_page_addr_t start, tb_page_addr_t end,
                              int is_cpu_write_access);
#if !defined(CONFIG_USER_ONLY)
/* cputlb.c */
void tlb_flush_page(CPUArchState *env, target_ulong addr);
void tlb_flush(CPUArchState *env, int flush_global);
void tlb_set_page(CPUArchState *env, target_ulong vaddr,
                  hwaddr paddr, int prot,
                  int mmu_idx, target_ulong size);
void tb_reset_jump_recursive(TranslationBlock *tb);
void tb_invalidate_phys_addr(hwaddr addr);
#else
static inline void tlb_flush_page(CPUArchState *env, target_ulong addr)
{
}

static inline void tlb_flush(CPUArchState *env, int flush_global)
{
}
#endif

typedef struct PhysPageDesc {
    /* offset in host memory of the page + io_index in the low bits */
    ram_addr_t phys_offset;
    ram_addr_t region_offset;
} PhysPageDesc;

PhysPageDesc *phys_page_find(hwaddr index);
PhysPageDesc *phys_page_find_alloc(hwaddr index, int alloc);

int io_mem_watch;

#define CODE_GEN_ALIGN           16 /* must be >= of the size of a icache line */

#define CODE_GEN_PHYS_HASH_BITS     15
#define CODE_GEN_PHYS_HASH_SIZE     (1 << CODE_GEN_PHYS_HASH_BITS)

/* estimated block size for TB allocation */
/* XXX: use a per code average code fragment size and modulate it
   according to the host CPU */
#if defined(CONFIG_SOFTMMU)
#define CODE_GEN_AVG_BLOCK_SIZE 128
#else
#define CODE_GEN_AVG_BLOCK_SIZE 64
#endif

#if defined(__arm__) || defined(_ARCH_PPC) \
    || defined(__x86_64__) || defined(__i386__) \
    || defined(__sparc__) || defined(__aarch64__) \
    || defined(CONFIG_TCG_INTERPRETER)
#define USE_DIRECT_JUMP
#endif

struct TranslationBlock {
    target_ulong pc;   /* simulated PC corresponding to this block (EIP + CS base) */
    target_ulong cs_base; /* CS base for this block */
    uint64_t flags; /* flags defining in which context the code was generated */
    uint16_t size;      /* size of target code for this block (1 <=
                           size <= TARGET_PAGE_SIZE) */
    uint16_t cflags;    /* compile flags */
#define CF_COUNT_MASK  0x7fff
#define CF_LAST_IO     0x8000 /* Last insn may be an IO access.  */

    uint8_t *tc_ptr;    /* pointer to the translated code */
    /* next matching tb for physical address. */
    struct TranslationBlock *phys_hash_next;
    /* first and second physical page containing code. The lower bit
       of the pointer tells the index in page_next[] */
    struct TranslationBlock *page_next[2];
    tb_page_addr_t page_addr[2];

    /* the following data are used to directly call another TB from
       the code of this one. */
    uint16_t tb_next_offset[2]; /* offset of original jump target */
#ifdef USE_DIRECT_JUMP
    uint16_t tb_jmp_offset[4]; /* offset of jump instruction */
#else
    uintptr_t tb_next[2]; /* address of jump generated code */
#endif
    /* list of TBs jumping to this one. This is a circular list using
       the two least significant bits of the pointers to tell what is
       the next pointer: 0 = jmp_next[0], 1 = jmp_next[1], 2 =
       jmp_first */
    struct TranslationBlock *jmp_next[2];
    struct TranslationBlock *jmp_first;
    uint32_t icount;

#ifdef CONFIG_ANDROID_MEMCHECK
    /* Maps PCs in this translation block to corresponding PCs in guest address
     * space. The array is arranged in such way, that every even entry contains
     * PC in the translation block, followed by an odd entry that contains
     * guest PC corresponding to that PC in the translation block. This
     * arrangement is set by tcg_gen_code_common that initializes this array
     * when performing guest code translation. */
    uintptr_t*   tpc2gpc;
    /* Number of pairs (pc_tb, pc_guest) in tpc2gpc array. */
    unsigned int    tpc2gpc_pairs;
#endif  // CONFIG_ANDROID_MEMCHECK
};

#include "exec/spinlock.h"

typedef struct TBContext TBContext;

struct TBContext {

    TranslationBlock *tbs;
    TranslationBlock *tb_phys_hash[CODE_GEN_PHYS_HASH_SIZE];
    int nb_tbs;
    /* any access to the tbs or the page table must use this lock */
    spinlock_t tb_lock;

    /* statistics */
    int tb_flush_count;
    int tb_phys_invalidate_count;

    int tb_invalidated_flag;
};

static inline unsigned int tb_jmp_cache_hash_page(target_ulong pc)
{
    target_ulong tmp;
    tmp = pc ^ (pc >> (TARGET_PAGE_BITS - TB_JMP_PAGE_BITS));
    return (tmp >> (TARGET_PAGE_BITS - TB_JMP_PAGE_BITS)) & TB_JMP_PAGE_MASK;
}

static inline unsigned int tb_jmp_cache_hash_func(target_ulong pc)
{
    target_ulong tmp;
    tmp = pc ^ (pc >> (TARGET_PAGE_BITS - TB_JMP_PAGE_BITS));
    return (((tmp >> (TARGET_PAGE_BITS - TB_JMP_PAGE_BITS)) & TB_JMP_PAGE_MASK)
	    | (tmp & TB_JMP_ADDR_MASK));
}

static inline unsigned int tb_phys_hash_func(tb_page_addr_t pc)
{
    return (pc >> 2) & (CODE_GEN_PHYS_HASH_SIZE - 1);
}

#ifdef CONFIG_ANDROID_MEMCHECK
/* Gets translated PC for a given (translated PC, guest PC) pair.
 * Return:
 *  Translated PC, or NULL if pair index was too large.
 */
static inline target_ulong
tb_get_tb_pc(const TranslationBlock* tb, unsigned int pair)
{
    return (tb->tpc2gpc != NULL && pair < tb->tpc2gpc_pairs) ?
                                                    tb->tpc2gpc[pair * 2] : 0;
}

/* Gets guest PC for a given (translated PC, guest PC) pair.
 * Return:
 *  Guest PC, or NULL if pair index was too large.
 */
static inline target_ulong
tb_get_guest_pc(const TranslationBlock* tb, unsigned int pair)
{
    return (tb->tpc2gpc != NULL && pair < tb->tpc2gpc_pairs) ?
            tb->tpc2gpc[pair * 2 + 1] : 0;
}

/* Gets guest PC for a given translated PC.
 * Return:
 *  Guest PC for a given translated PC, or NULL if there was no pair, matching
 *  translated PC in tb's tpc2gpc array.
 */
static inline target_ulong
tb_search_guest_pc_from_tb_pc(const TranslationBlock* tb, target_ulong tb_pc)
{
    if (tb->tpc2gpc != NULL && tb->tpc2gpc_pairs != 0) {
        unsigned int m_min = 0;
        unsigned int m_max = (tb->tpc2gpc_pairs - 1) << 1;
        /* Make sure that tb_pc is within TB array. */
        if (tb_pc < tb->tpc2gpc[0]) {
            return 0;
        }
        while (m_min <= m_max) {
            const unsigned int m = ((m_min + m_max) >> 1) & ~1;
            if (tb_pc < tb->tpc2gpc[m]) {
                m_max = m - 2;
            } else if (m == m_max || tb_pc < tb->tpc2gpc[m + 2]) {
                return tb->tpc2gpc[m + 1];
            } else {
                m_min = m + 2;
            }
        }
        return tb->tpc2gpc[m_max + 1];
    }
    return 0;
}
#endif  // CONFIG_ANDROID_MEMCHECK

void tb_free(TranslationBlock *tb);
void tb_flush(CPUArchState *env);
void tb_link_phys(TranslationBlock *tb,
                  target_ulong phys_pc, target_ulong phys_page2);
void tb_phys_invalidate(TranslationBlock *tb, tb_page_addr_t page_addr);
void tb_invalidate_phys_page_fast0(hwaddr start, int len);
    
extern uint8_t *code_gen_ptr;
extern int code_gen_max_blocks;

#if defined(USE_DIRECT_JUMP)

#if defined(CONFIG_TCG_INTERPRETER)
static inline void tb_set_jmp_target1(uintptr_t jmp_addr, uintptr_t addr)
{
    /* patch the branch destination */
    *(uint32_t *)jmp_addr = addr - (jmp_addr + 4);
    /* no need to flush icache explicitly */
}
#elif defined(_ARCH_PPC)
void ppc_tb_set_jmp_target(unsigned long jmp_addr, unsigned long addr);
#define tb_set_jmp_target1 ppc_tb_set_jmp_target
#elif defined(__i386__) || defined(__x86_64__)
static inline void tb_set_jmp_target1(uintptr_t jmp_addr, uintptr_t addr)
{
    /* patch the branch destination */
    *(uint32_t *)jmp_addr = addr - (jmp_addr + 4);
    /* no need to flush icache explicitly */
}
#elif defined(__aarch64__)
void aarch64_tb_set_jmp_target(uintptr_t jmp_addr, uintptr_t addr);
#define tb_set_jmp_target1 aarch64_tb_set_jmp_target
#elif defined(__arm__)
static inline void tb_set_jmp_target1(uintptr_t jmp_addr, uintptr_t addr)
{
#if !QEMU_GNUC_PREREQ(4, 1)
    register unsigned long _beg __asm ("a1");
    register unsigned long _end __asm ("a2");
    register unsigned long _flg __asm ("a3");
#endif

    /* we could use a ldr pc, [pc, #-4] kind of branch and avoid the flush */
    *(uint32_t *)jmp_addr =
        (*(uint32_t *)jmp_addr & ~0xffffff)
        | (((addr - (jmp_addr + 8)) >> 2) & 0xffffff);

#if QEMU_GNUC_PREREQ(4, 1)
    __builtin___clear_cache((char *) jmp_addr, (char *) jmp_addr + 4);
#else
    /* flush icache */
    _beg = jmp_addr;
    _end = jmp_addr + 4;
    _flg = 0;
    __asm __volatile__ ("swi 0x9f0002" : : "r" (_beg), "r" (_end), "r" (_flg));
#endif
}
#elif defined(__sparc__)
void tb_set_jmp_target1(uintptr_t jmp_addr, uintptr_t addr);
#else
#error tb_set_jmp_target1 is missing
#endif

static inline void tb_set_jmp_target(TranslationBlock *tb,
                                     int n, uintptr_t addr)
{
    uint16_t offset = tb->tb_jmp_offset[n];
    tb_set_jmp_target1((uintptr_t)(tb->tc_ptr + offset), addr);
    offset = tb->tb_jmp_offset[n + 2];
    if (offset != 0xffff)
        tb_set_jmp_target1((uintptr_t)(tb->tc_ptr + offset), addr);
}

#else

/* set the jump target */
static inline void tb_set_jmp_target(TranslationBlock *tb,
                                     int n, uintptr_t addr)
{
    tb->tb_next[n] = addr;
}

#endif

static inline void tb_add_jump(TranslationBlock *tb, int n,
                               TranslationBlock *tb_next)
{
    /* NOTE: this test is only needed for thread safety */
    if (!tb->jmp_next[n]) {
        /* patch the native jump address */
        tb_set_jmp_target(tb, n, (uintptr_t)tb_next->tc_ptr);

        /* add in TB jmp circular list */
        tb->jmp_next[n] = tb_next->jmp_first;
        tb_next->jmp_first = (TranslationBlock *)((uintptr_t)(tb) | (n));
    }
}

/* GETRA is the true target of the return instruction that we'll execute,
   defined here for simplicity of defining the follow-up macros.  */
#if defined(CONFIG_TCG_INTERPRETER)
extern uintptr_t tci_tb_ptr;
# define GETRA() tci_tb_ptr
#else
# define GETRA() \
    ((uintptr_t)__builtin_extract_return_addr(__builtin_return_address(0)))
#endif

/* The true return address will often point to a host insn that is part of
   the next translated guest insn.  Adjust the address backward to point to
   the middle of the call insn.  Subtracting one would do the job except for
   several compressed mode architectures (arm, mips) which set the low bit
   to indicate the compressed mode; subtracting two works around that.  It
   is also the case that there are no host isas that contain a call insn
   smaller than 4 bytes, so we don't worry about special-casing this.  */
#if defined(CONFIG_TCG_INTERPRETER)
# define GETPC_ADJ   0
#else
# define GETPC_ADJ   2
#endif

#define GETPC()  (GETRA() - GETPC_ADJ)

#if !defined(CONFIG_USER_ONLY)

void phys_mem_set_alloc(void *(*alloc)(size_t));

TranslationBlock *tb_find_pc(uintptr_t pc_ptr);

uint64_t io_mem_read(int index, hwaddr addr, unsigned size);
void io_mem_write(int index, hwaddr addr, uint64_t value, unsigned size);

extern CPUWriteMemoryFunc *_io_mem_write[IO_MEM_NB_ENTRIES][4];
extern CPUReadMemoryFunc *_io_mem_read[IO_MEM_NB_ENTRIES][4];
extern void *io_mem_opaque[IO_MEM_NB_ENTRIES];

void tlb_fill(CPUArchState *env1, target_ulong addr, int is_write, int mmu_idx,
              uintptr_t retaddr);

#include "exec/softmmu_defs.h"

#define ACCESS_TYPE (NB_MMU_MODES + 1)
#define MEMSUFFIX _code
#define env cpu_single_env

#define DATA_SIZE 1
#include "exec/softmmu_header.h"

#define DATA_SIZE 2
#include "exec/softmmu_header.h"

#define DATA_SIZE 4
#include "exec/softmmu_header.h"

#define DATA_SIZE 8
#include "exec/softmmu_header.h"

#undef ACCESS_TYPE
#undef MEMSUFFIX
#undef env

#endif

#if defined(CONFIG_USER_ONLY)
static inline tb_page_addr_t get_page_addr_code(CPUArchState *env1, target_ulong addr)
{
    return addr;
}
#else
tb_page_addr_t get_page_addr_code(CPUArchState *env1, target_ulong addr);
#endif

typedef void (CPUDebugExcpHandler)(CPUArchState *env);

void cpu_set_debug_excp_handler(CPUDebugExcpHandler *handler);

/* vl.c */
extern int singlestep;

/* cpu-exec.c */
extern volatile sig_atomic_t exit_request;

/* Deterministic execution requires that IO only be performed on the last
   instruction of a TB so that interrupts take effect immediately.  */
static inline int can_do_io(CPUArchState *env)
{
    if (!use_icount) {
        return 1;
    }
    /* If not executing code then assume we are ok.  */
    if (env->current_tb == NULL) {
        return 1;
    }
    return env->can_do_io != 0;
}

#endif
