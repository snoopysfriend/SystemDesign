// SPDX-License-Identifier: GPL-2.0-only
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <assert.h>

#define PAGE_SHIFT 12
#define PAGE_SIZE  (1<<PAGE_SHIFT)
#define PTE_MASK ((1<<9)-1)


struct expose_pte_args {
	pid_t pid;
	unsigned long begin_fpt_vaddr;
	unsigned long end_fpt_vaddr;
	unsigned long begin_pte_vaddr;
	unsigned long end_pte_vaddr;
	unsigned long begin_vaddr;
	unsigned long end_vaddr;
};

unsigned int pte_offset(unsigned long addr)
{
	//printf("%x %x\n", PAGE_SIZE, PTE_MASK);
	return (unsigned int)((addr >> PAGE_SHIFT) & PTE_MASK);
}

unsigned long align(unsigned long addr, unsigned long mask)
{
	return (addr + mask) & (~(mask-1));
}

unsigned long pte_to_phys(unsigned long val)
{
	//printf("%lx\n", val);
	return val & ((1ULL<<48)-1) << PAGE_SHIFT;
}

int main(int argc, char **argv)
{
	struct expose_pte_args expose;
	unsigned long size = 4 * PAGE_SIZE;
	unsigned long begin_vaddr, end_vaddr;
	unsigned int offset;
	unsigned long *remapped_pte;
	int pte = 0, i = 0;

	if (argc != 5) {
		printf("[Error] ./hw3-test -i <pid> <begin_va> <end_va>\n");
		return -1;
	}
	/* TODO check the argument */
	expose.pid = atoi(argv[2]);
	begin_vaddr = strtoul(argv[3], NULL, 0);
	end_vaddr = strtoul(argv[4], NULL, 0);

	/* allocate map for pte and fpt */
	unsigned long *pte_buff = mmap(NULL, size, PROT_READ |
			PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, 0, 0);
	if (pte_buff == MAP_FAILED) {
		printf("mmap error !\n");
		return -1;
	}
	/* TODO if fpt mmap will page fault */
	unsigned long *fpt_buff = malloc(size);

	/* init expose addr  */
	expose.begin_vaddr = begin_vaddr;
	expose.end_vaddr = end_vaddr;
	expose.begin_fpt_vaddr = (unsigned long)fpt_buff;
	expose.end_fpt_vaddr = (unsigned long)fpt_buff + size;
	expose.begin_pte_vaddr = (unsigned long)pte_buff;
	expose.end_pte_vaddr = (unsigned long)pte_buff + size;
	/* syscall */
	if (syscall(436, &expose) != 0) {
		printf("[Error] syscall expose pte error\n");
		return -1;
	}
	unsigned long phys_addr;

	unsigned long PMD_SIZE = PAGE_SIZE * (1<<9);
	unsigned long aligned_addr = align(begin_vaddr, PMD_SIZE);


	while (begin_vaddr <= end_vaddr) {
		if (align(begin_vaddr, PMD_SIZE) != aligned_addr) {
			pte++;
			aligned_addr = align(begin_vaddr, PTE_MASK);
		}
		remapped_pte = ((unsigned long**)fpt_buff)[pte];
		if (remapped_pte) {
			offset = pte_offset(begin_vaddr);
			phys_addr = pte_to_phys(remapped_pte[offset]);
			printf("va%d 0x%lx pa%d 0x%lx\n", i, begin_vaddr, i, phys_addr);
		} else {
			printf("va%d 0x%lx pa%d (nil)\n", i, begin_vaddr, i);
		}
		begin_vaddr += PAGE_SIZE;
		i++;
	}


	return 0;
}
