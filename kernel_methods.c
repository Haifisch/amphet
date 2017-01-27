/*
 * kernel_methods.c
 * Copyright (c) 2014 Samuel Groß
 * Copyright (c) 2016 Siguza
 * Copyrihgt (c) 2016-2017 Haifisch
 */

#include <stdbool.h>            // bool, true, false
#include <stdint.h>             // uint32_t, uint64_t
#include <stdio.h>              // printf, fprintf, stderr
#include <stdlib.h>             // free, malloc

#include <mach/mach_init.h>
#include <mach/mach_error.h>
#include <mach/mach_traps.h>
#include <mach/mach_types.h>
#include <mach/host_priv.h>
#include <mach/vm_map.h>

#include "arch.h"               // mach_hdr_t
#include "libkern.h"            // get_kernel_task, get_kernel_base, read_kernel
#include "mach-o.h"             // CMD_ITERATE
#include "kernel_methods.h"

#define MAX_HEADER_SIZE 0x2000

typedef struct
{
    char r;
    char w;
    char x;
} rwx_t;

static rwx_t parse_rwx(vm_prot_t prot)
{
    rwx_t rwx;
    rwx.r = prot & VM_PROT_READ ? 'r' : '-';
    rwx.w = prot & VM_PROT_WRITE ? 'w' : '-';
    rwx.x = prot & VM_PROT_EXECUTE ? 'x' : '-';
    return rwx;
}

static char* get_segment_flag_name(uint32_t b)
{
    switch(b)
    {
        case SG_HIGHVM:                 return "highvm";
        case SG_FVMLIB:                 return "fvmlib";
        case SG_NORELOC:                return "noreloc";
        case SG_PROTECTED_VERSION_1:    return "protect";
    }
    return NULL;
}

// Printing is just so much easier than in-memory concatting
static void print_segment_flags(uint32_t bits)
{
    if(bits == 0)
    {
        printf("none");
        return;
    }
    bool previous = false;
    char *name;
    for(uint32_t b = 1; bits > 0; b <<= 1)
    {
        if(bits & b)
        {
            name = get_segment_flag_name(b);
            if(name == NULL)
                printf("%sunknown(0x%02x)", previous ? "," : "", b);
            else
                printf("%s%s", previous ? "," : "", name);
            previous= true;
            bits ^= b;
        }
    }
}

static char* get_section_type(uint32_t bits)
{
    switch(bits & SECTION_TYPE)
    {
        case S_REGULAR:                             return "S_REGULAR";
        case S_ZEROFILL:                            return "S_ZEROFILL";
        case S_CSTRING_LITERALS:                    return "S_CSTRING_LITERALS";
        case S_4BYTE_LITERALS:                      return "S_4BYTE_LITERALS";
        case S_8BYTE_LITERALS:                      return "S_8BYTE_LITERALS";
        case S_LITERAL_POINTERS:                    return "S_LITERAL_POINTERS";
        case S_NON_LAZY_SYMBOL_POINTERS:            return "S_NON_LAZY_SYMBOL_POINTERS";
        case S_LAZY_SYMBOL_POINTERS:                return "S_LAZY_SYMBOL_POINTERS";
        case S_SYMBOL_STUBS:                        return "S_SYMBOL_STUBS";
        case S_MOD_INIT_FUNC_POINTERS:              return "S_MOD_INIT_FUNC_POINTERS";
        case S_MOD_TERM_FUNC_POINTERS:              return "S_MOD_TERM_FUNC_POINTERS";
        case S_COALESCED:                           return "S_COALESCED";
        case S_GB_ZEROFILL:                         return "S_GB_ZEROFILL";
        case S_INTERPOSING:                         return "S_INTERPOSING";
        case S_16BYTE_LITERALS:                     return "S_16BYTE_LITERALS";
        case S_DTRACE_DOF:                          return "S_DTRACE_DOF";
        case S_LAZY_DYLIB_SYMBOL_POINTERS:          return "S_LAZY_DYLIB_SYMBOL_POINTERS";
        case S_THREAD_LOCAL_REGULAR:                return "S_THREAD_LOCAL_REGULAR";
        case S_THREAD_LOCAL_ZEROFILL:               return "S_THREAD_LOCAL_ZEROFILL";
        case S_THREAD_LOCAL_VARIABLES:              return "S_THREAD_LOCAL_VARIABLES";
        case S_THREAD_LOCAL_VARIABLE_POINTERS:      return "S_THREAD_LOCAL_VARIABLE_POINTERS";
        case S_THREAD_LOCAL_INIT_FUNCTION_POINTERS: return "S_THREAD_LOCAL_INIT_FUNCTION_POINTERS";
    }
    return "unknown";
}

static char* get_section_attribute_name(uint32_t b)
{
    switch(b)
    {
        case S_ATTR_LOC_RELOC:              return "S_ATTR_LOC_RELOC";
        case S_ATTR_EXT_RELOC:              return "S_ATTR_EXT_RELOC";
        case S_ATTR_SOME_INSTRUCTIONS:      return "S_ATTR_SOME_INSTRUCTIONS";
        case S_ATTR_DEBUG:                  return "S_ATTR_DEBUG";
        case S_ATTR_SELF_MODIFYING_CODE:    return "S_ATTR_SELF_MODIFYING_CODE";
        case S_ATTR_LIVE_SUPPORT:           return "S_ATTR_LIVE_SUPPORT";
        case S_ATTR_NO_DEAD_STRIP:          return "S_ATTR_NO_DEAD_STRIP";
        case S_ATTR_STRIP_STATIC_SYMS:      return "S_ATTR_STRIP_STATIC_SYMS";
        case S_ATTR_NO_TOC:                 return "S_ATTR_NO_TOC";
        case S_ATTR_PURE_INSTRUCTIONS:      return "S_ATTR_PURE_INSTRUCTIONS";
    }
    return "unknown";
}

static void print_section_attributes(uint32_t bits)
{
    bits &= SECTION_ATTRIBUTES;
    if(bits == 0)
    {
        printf("none");
        return;
    }
    bool previous = false;
    char *name;
    for(uint32_t b = SECTION_TYPE + 1; bits > 0; b <<= 1)
    {
        if(bits & b)
        {
            name = get_section_attribute_name(b);
            if(name == NULL)
                printf("%sunknown(0x%08x)", previous ? "," : "", b);
            else
                printf("%s%s", previous ? "," : "", name);
            previous= true;
            bits ^= b;
        }
    }
}

int print_kernel_header() {
	task_t kernel_task;
    vm_address_t kbase;
    unsigned char *buf;
    mach_hdr_t *hdr;
    struct segment_command_64 *seg64;
    struct segment_command *seg32;
    struct section_64 *sec64;
    struct section *sec32;
    struct symtab_command *symtab;
    uint64_t *uuid;
    struct version_min_command *vers;
    rwx_t init_rwx, max_rwx;
    int i;

    buf = malloc(MAX_HEADER_SIZE);
    if(buf == NULL)
    {
        fprintf(stderr, "[!] Failed to allocate header buffer\n");
        return -1;
    }
    hdr = (mach_hdr_t*)buf;

    if(get_kernel_task(&kernel_task) != KERN_SUCCESS)
    {
        fprintf(stderr, "[!] Failed to get kernel task\n");
        return -1;
    }

    if((kbase = get_kernel_base()) == 0)
    {
        fprintf(stderr, "[!] Failed to locate kernel\n");
        return -1;
    }

    read_kernel(kbase, MAX_HEADER_SIZE, buf);
    CMD_ITERATE(hdr, cmd)
    {
        switch(cmd->cmd)
        {
            case LC_SEGMENT:
                seg32 = (struct segment_command*)cmd;
                init_rwx = parse_rwx(seg32->initprot);
                max_rwx = parse_rwx(seg32->maxprot);
                printf("LC_SEGMENT:\n"
                       "    name:                       %s\n"
                       "    size:                       0x%08x\n"
                       "    file offset/length:         0x%08x/0x%08x\n"
                       "    memory offset/length:       0x%08x/0x%08x\n"
                       "    initial/max permissions:    %c%c%c/%c%c%c\n"
                       "    flags:                      ",
                       seg32->segname, seg32->cmdsize, seg32->vmaddr, seg32->vmsize, seg32->fileoff, seg32->filesize,
                       init_rwx.r, init_rwx.w, init_rwx.x, max_rwx.r, max_rwx.w, max_rwx.x);
                print_segment_flags(seg32->flags);
                printf("\n");
                for(i = 0; i < seg32->nsects; ++i)
                {
                    sec32 = (struct section*)(seg32 + 1) + i;
                    printf("    section:\n"
                           "        name:                   %s.%s\n"
                           "        type:                   %s\n"
                           "        size:                   0x%08x\n"
                           "        file offset:            0x%08x\n"
                           "        memory offset:          0x%08x\n"
                           "        align:                  %10u\n",
                           sec32->segname, sec32->sectname, get_section_type(sec32->flags),
                           sec32->size, sec32->offset, sec32->addr, sec32->align);
                    if(sec32->nreloc > 0)
                    {
                        printf("        reloc addr:             0x%08x\n"
                               "        reloc count:            %10u\n",
                               sec32->reloff, sec32->nreloc);
                    }
                    printf("        attributes:             ");
                    print_section_attributes(sec32->flags);
                    printf("\n");
                }
                break;
            case LC_SEGMENT_64:
                seg64 = (struct segment_command_64*)cmd;
                init_rwx = parse_rwx(seg64->initprot);
                max_rwx = parse_rwx(seg64->maxprot);
                printf("LC_SEGMENT_64:\n"
                       "    name:                       %s\n"
                       "    size:                       0x%08x\n"
                       "    file offset/length:         0x%016llx/0x%016llx\n"
                       "    memory offset/length:       0x%016llx/0x%016llx\n"
                       "    initial/max permissions:    %c%c%c/%c%c%c\n"
                       "    flags:                      ",
                       seg64->segname, seg64->cmdsize, seg64->fileoff, seg64->filesize, seg64->vmaddr, seg64->vmsize,
                       init_rwx.r, init_rwx.w, init_rwx.x, max_rwx.r, max_rwx.w, max_rwx.x);
                print_segment_flags(seg64->flags);
                printf("\n");
                for(i = 0; i < seg64->nsects; ++i)
                {
                    sec64 = (struct section_64*)(seg64 + 1) + i;
                    printf("    section:\n"
                           "        name:                   %s.%s\n"
                           "        type:                   %s\n"
                           "        size:                   0x%016llx\n"
                           "        file offset:            0x%016x\n"
                           "        memory offset:          0x%016llx\n"
                           "        align:                  %18u\n",
                           sec64->segname, sec64->sectname, get_section_type(sec64->flags),
                           sec64->size, sec64->offset, sec64->addr, sec64->align);
                    if(sec64->nreloc > 0)
                    {
                        printf("        reloc addr:             0x%016x\n"
                               "        reloc count:            %18u\n",
                               sec64->reloff, sec64->nreloc);
                    }
                    printf("        attributes:             ");
                    print_section_attributes(sec64->flags);
                    printf("\n");
                }
                break;
            case LC_SYMTAB:
                symtab = (struct symtab_command*)cmd;
                printf("LC_SYMTAB:\n"
                       "    symbol table offset:        0x%08x\n"
                       "    symbol table count:         0x%08x\n"
                       "    string table offset:        0x%08x\n"
                       "    string table size:          0x%08x\n",
                       symtab->symoff, symtab->nsyms, symtab->stroff, symtab->strsize);
                break;
            case LC_UUID:
                uuid = (uint64_t*)((struct uuid_command*)cmd)->uuid;
                printf("LC_UUID:                        0x%016llx%016llx\n",
                       uuid[1], uuid[0]);
                break;
            case LC_VERSION_MIN_MACOSX:
            case LC_VERSION_MIN_IPHONEOS:
            case LC_VERSION_MIN_TVOS:
            case LC_VERSION_MIN_WATCHOS:
                vers = (struct version_min_command*)cmd;
                printf("%s:\n"
                       "    version:                    %u.%u.%u\n"
                       "    sdk:                        %u.%u.%u\n",
                       cmd->cmd == LC_VERSION_MIN_MACOSX ? "LC_VERSION_MIN_MACOSX" :
                       cmd->cmd == LC_VERSION_MIN_IPHONEOS ? "LC_VERSION_MIN_IPHONEOS" :
                       cmd->cmd == LC_VERSION_MIN_TVOS ? "LC_VERSION_MIN_TVOS" : "LC_VERSION_MIN_WATCHOS",
                       (vers->version >> 16) & 0xffff, (vers->version >> 8) & 0xff, vers->version & 0xff,
                       (vers->sdk     >> 16) & 0xffff, (vers->sdk     >> 8) & 0xff, vers->sdk     & 0xff);
                break;
            default:
                printf("Unknown load command: 0x%08x\n", cmd->cmd);
                break;
                /*
                LC_SYMSEG                   0x3
                LC_THREAD                   0x4
                LC_UNIXTHREAD               0x5
                LC_LOADFVMLIB               0x6
                LC_IDFVMLIB                 0x7
                LC_IDENT                    0x8
                LC_FVMFILE                  0x9
                LC_PREPAGE                  0xa
                LC_DYSYMTAB                 0xb
                LC_LOAD_DYLIB               0xc
                LC_ID_DYLIB                 0xd
                LC_LOAD_DYLINKER            0xe
                LC_ID_DYLINKER              0xf
                LC_PREBOUND_DYLIB           0x10
                LC_ROUTINES                 0x11
                LC_SUB_FRAMEWORK            0x12
                LC_SUB_UMBRELLA             0x13
                LC_SUB_CLIENT               0x14
                LC_SUB_LIBRARY              0x15
                LC_TWOLEVEL_HINTS           0x16
                LC_PREBIND_CKSUM            0x17
                LC_LOAD_WEAK_DYLIB          (0x18 | LC_REQ_DYLD)
                LC_ROUTINES_64              0x1a
                LC_RPATH                    (0x1c | LC_REQ_DYLD)
                LC_CODE_SIGNATURE           0x1d
                LC_SEGMENT_SPLIT_INFO       0x1e
                LC_REEXPORT_DYLIB           (0x1f | LC_REQ_DYLD)
                LC_LAZY_LOAD_DYLIB          0x20
                LC_ENCRYPTION_INFO          0x21
                LC_DYLD_INFO                0x22
                LC_DYLD_INFO_ONLY           (0x22|LC_REQ_DYLD)
                LC_LOAD_UPWARD_DYLIB        (0x23 | LC_REQ_DYLD)
                LC_FUNCTION_STARTS          0x26
                LC_DYLD_ENVIRONMENT         0x27
                LC_MAIN                     (0x28|LC_REQ_DYLD)
                LC_DATA_IN_CODE             0x29
                LC_SOURCE_VERSION           0x2A
                LC_DYLIB_CODE_SIGN_DRS      0x2B
                LC_ENCRYPTION_INFO_64       0x2C
                LC_LINKER_OPTION            0x2D
                LC_LINKER_OPTIMIZATION_HINT 0x2E
                */
        }
    }

    free(buf);
    return 0;
}

int print_kernel_map() {
	kern_return_t ret;
    task_t kernel_task;

    ret = task_for_pid(mach_task_self(), 0, &kernel_task);
    if (ret != KERN_SUCCESS) {
        printf("[!] failed to access the kernel task");
        return -1;
    }

    vm_region_submap_info_data_64_t info;
    vm_size_t size;
    mach_msg_type_number_t info_count = VM_REGION_SUBMAP_INFO_COUNT_64;
    unsigned int depth = 0;
    vm_address_t addr = 0x80000000;
    size_t displaysize;
    char scale;
    char curR, curW, curX, maxR, maxW, maxX;

    while (1) {
        // get next memory region
        ret = vm_region_recurse_64(kernel_task, &addr, &size, &depth, (vm_region_info_t)&info, &info_count);

        if (ret != KERN_SUCCESS)
            break;

        // size
        scale = 'K';
        displaysize = size / 1024;
        if (displaysize > 99999) {
            scale = 'M';
            displaysize /= 1024;
        }

        // protection
        curR = (info.protection) & VM_PROT_READ ? 'r' : '-';
        curW = (info.protection) & VM_PROT_WRITE ? 'w' : '-';
        curX = (info.protection) & VM_PROT_EXECUTE ? 'x' : '-';
        maxR = (info.max_protection) & VM_PROT_READ ? 'r' : '-';
        maxW = (info.max_protection) & VM_PROT_WRITE ? 'w' : '-';
        maxX = (info.max_protection) & VM_PROT_EXECUTE ? 'x' : '-';

        printf(ADDR "-" ADDR " [%5zu%c] %c%c%c/%c%c%c\n",
               addr, addr+size, displaysize, scale,
               curR, curW, curX, maxR, maxW, maxX);

        addr += size;
    }

    return 0;
}