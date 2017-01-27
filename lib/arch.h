/*
 * arch.h - Code to deal with different architectures.
 *
 * Copyright (c) 2014 Samuel Groß
 * Copyright (c) 2016 Siguza
 */

#ifndef ARCH_H
#define ARCH_H

#include <mach-o/loader.h>      // mach_header, mach_header_64, segment_command, segment_command_64

#if __LP64__
#   define ADDR "%016lx"
#   define SIZE "%lu"
#   define IMAGE_OFFSET 0x2000
#   define MACH_TYPE CPU_TYPE_ARM64
#   define MACH_HEADER_MAGIC MH_MAGIC_64
    typedef struct mach_header_64 mach_hdr_t;
    typedef struct segment_command_64 mach_seg_t;
#else
#   define ADDR "%08x"
#   define SIZE "%u"
#   define IMAGE_OFFSET 0x1000
#   define MACH_TYPE CPU_TYPE_ARM
#   define MACH_HEADER_MAGIC MH_MAGIC
    typedef struct mach_header mach_hdr_t;
    typedef struct segment_command mach_seg_t;
#endif

#endif
