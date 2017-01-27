/*
 * libkern.h - Everything that touches the kernel.
 *
 * Copyright (c) 2014 Samuel Groß
 * Copyright (c) 2016 Siguza
 */

#ifndef LIBKERN_H
#define LIBKERN_H

#include <mach/kern_return.h>   // kern_return_t
#include <mach/mach_types.h>    // task_t
#include <mach/vm_types.h>      // vm_address_t, vm_size_t

/*
 * Functions to interact with the kernel address space.
 *
 * If not otherwise stated the following functions are 'unsafe', meaning
 * they are likely to panic the device if given invalid kernel addresses.
 *
 * You have been warned.
 */

/*
 * Get the kernel task port.
 *
 * This function should be safe at least on iOS 8 and earlier.
 */

kern_return_t get_kernel_task(task_t *task);

/*
 * Return the base address of the running kernel.
 *
 * This function should be safe at least on iOS 8 and earlier.
 */
vm_address_t get_kernel_base();

/*
 * Read data from the kernel address space.
 *
 * Returns the number of bytes read.
 */
vm_size_t read_kernel(vm_address_t addr, vm_size_t size, unsigned char* buf);

/*
 * Write data into the kernel address space.
 *
 * Returns the number of bytes written.
 */
vm_size_t write_kernel(vm_address_t addr, unsigned char* data, vm_size_t size);

/*
 * Find the given byte sequence in the kernel address space between start and end.
 *
 * Returns the address of the first occurance of bytes if found, otherwise 0.
 */
vm_address_t find_bytes_kern(vm_address_t start, vm_address_t end, unsigned char* bytes, size_t length);


//custom thanjs jk
uint32_t findStringInKernel(const char *string,mach_port_t special_port,uint32_t kernel_base);
uint32_t findBytesInKernel(uint8_t bytesToFind[],unsigned long len,mach_port_t special_port,uint32_t kernel_base);
#endif
