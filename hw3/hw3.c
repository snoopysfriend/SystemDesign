#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <sys/mman.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <assert.h>
#include <stdint.h>

#ifndef BONUS
#include "sc.asm"
#else
#include "sc-bonus.asm"
#endif

#define PAGE_SHIFT 12
#define PAGE_SIZE  (1<<PAGE_SHIFT)
#define PTE_MASK ((1<<9)-1)
#define PMD_SIZE (PAGE_SIZE * (1<<9))
#define PTE_SIZE (4 * PAGE_SIZE)

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
	return (unsigned int)((addr >> PAGE_SHIFT) & PTE_MASK);
}

unsigned long align(unsigned long addr, unsigned long mask)
{
	return (addr + mask) & (~(mask-1));
}

unsigned long pte_to_phys(unsigned long val)
{
	return val & ((1ULL<<48)-1) << PAGE_SHIFT;
}

extern void shellcode();

char *create_shellcode(unsigned long len) {
	int i;
	char *shellcode_addr;

	// allocate memory page
	shellcode_addr = (char*)mmap(NULL, len,
			PROT_READ | PROT_WRITE | PROT_EXEC, MAP_SHARED | MAP_ANONYMOUS, -1, 0);

	if (!shellcode_addr) {
		fprintf(stderr, "error: %s\n", strerror(errno));
		exit(-1);
	};

	// fill memory with nop instructions
	for (i = 0; i < len/4; i++) {
		((int*)shellcode_addr)[i] = 0xd503201f;  // nop opcode
	};

	// copy shellcode to memory page
	// TODO: replace |0x100| with your shellcode length
	for (i = 0; i < len / PAGE_SIZE; i++) {
		memcpy(shellcode_addr + (i+1) * PAGE_SIZE - 0x100, &shellcode, 0x100);
	}

	return shellcode_addr;
}


struct expose_pte_args get_expose(pid_t pid, unsigned long begin, unsigned long end) {
	struct expose_pte_args expose;
	/* allocate map for pte and fpt */
	unsigned long *pte_buff = mmap(NULL, PTE_SIZE, PROT_READ |
			PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, 0, 0);
	if (pte_buff == MAP_FAILED) {
		printf("mmap error !\n");
		exit(-1);
	}
	/* TODO if fpt mmap will page fault */
	unsigned long *fpt_buff = malloc(PTE_SIZE);

	expose.pid = pid;
	expose.begin_vaddr = begin;
	expose.end_vaddr = end;
	expose.begin_fpt_vaddr = (uintptr_t)fpt_buff;
	expose.end_fpt_vaddr = (uintptr_t)fpt_buff + PTE_SIZE;
	expose.begin_pte_vaddr = (unsigned long)pte_buff;
	expose.end_pte_vaddr = (unsigned long)pte_buff + PTE_SIZE;

	/* syscall */
	if (syscall(436, &expose) != 0) {
		printf("[Error] syscall expose pte error\n");
		exit(-1);
	}
	return expose;
}

void get_shell_pa(uintptr_t shell_va, size_t shell_size, uint64_t *shell_pa[]) {
	unsigned long begin = shell_va;
	unsigned long end = shell_va + shell_size;
	
	struct expose_pte_args expose = get_expose(getpid(), begin, end);

	int pte = 0, i = 0;
	unsigned long aligned_addr = align(begin, PMD_SIZE);

	while (begin < end) {
		if (align(begin, PMD_SIZE) != aligned_addr) {
			pte++;
			aligned_addr = align(begin, PTE_MASK);
		}
		unsigned long *remapped_pte = ((unsigned long**)expose.begin_fpt_vaddr)[pte];
		if (remapped_pte) {
			unsigned long offset = pte_offset(begin);
			shell_pa[i] = &remapped_pte[offset];
		} else {
			printf("[Error] remapped_pte (nil)\n");
			exit(-1);
		}
		begin += PAGE_SIZE;
		i++;
	}
}

void inject(unsigned long **arr, int num, pid_t pid, unsigned long begin_vaddr, unsigned long end_vaddr) {
	struct expose_pte_args expose = get_expose(pid, begin_vaddr, end_vaddr);

	int pte = 0, i = 0;

	unsigned long aligned_addr = align(begin_vaddr, PMD_SIZE);

	while (begin_vaddr <= end_vaddr && i < num) {
		if (align(begin_vaddr, PMD_SIZE) != aligned_addr) {
			pte++;
			aligned_addr = align(begin_vaddr, PTE_MASK);
		}
		unsigned long *remapped_pte = ((unsigned long**)expose.begin_fpt_vaddr)[pte];
		if (remapped_pte) {
			unsigned int offset = pte_offset(begin_vaddr);
			unsigned long phys_addr = pte_to_phys(remapped_pte[offset]);

			unsigned long tmp_arr = *arr[i];
			unsigned long tmp_pte = remapped_pte[offset];

			/* TODO: fix this */
			if (!tmp_arr || !tmp_pte) break;

			// const unsigned long mem_mask = ((1ULL << 36) - 1) << 12;

			*arr[i] = tmp_pte;
			remapped_pte[offset] = tmp_arr;

			//*arr[i] = (*arr[i] & ~mem_mask) | (tmp_pte & mem_mask);
			//remapped_pte[offset] = (remapped_pte[offset] & ~mem_mask) | (tmp_arr & mem_mask);

			//*arr[i] = (*arr[i] >> PAGE_SHIFT << PAGE_SHIFT) | (tmp_arr & ((1 << PAGE_SHIFT) - 1));
			//remapped_pte[i] = (remapped_pte[i] >> PAGE_SHIFT << PAGE_SHIFT) | (tmp_pte & ((1 << PAGE_SHIFT) - 1));

			//printf("[ARR]: %lx\n", tmp_arr >> 48);
			//printf("[PTE]: %lx\n", tmp_pte >> 48);
			//printf("[ARRS]: %lx\n", (tmp_arr >> 12) & 3);
			//printf("[PTES]: %lx\n", (tmp_pte >> 12) & 3);

			printf("va%d 0x%lx ", i, begin_vaddr);
			printf("pa%d 0x%lx -> 0x%lx\n", i, phys_addr, pte_to_phys(remapped_pte[offset]));
		} else {
			printf("[ERROR]\n");
			exit(-1);
		}
		begin_vaddr += PAGE_SIZE;
		i++;
	}
}

int main(int argc, char* argv[])
{
	if (argc != 3 && argc != 5) {
		printf("[Error] ./hw3 -i <pid> [begin end]\n");
		return -1;
	}
	pid_t pid = atoi(argv[2]);
	unsigned long begin_vaddr;
	unsigned long end_vaddr;
	
	if (argc == 3) {
		char fname[100];
		sprintf(fname, "/proc/%d/maps", pid);
		FILE *fp = fopen(fname, "r");
		fscanf(fp, "%lx-%lx", &begin_vaddr, &end_vaddr);
		printf("! 0x%lx 0x%lx\n", begin_vaddr, end_vaddr);
	} else {
		begin_vaddr = strtoul(argv[3], NULL, 0);
		end_vaddr = strtoul(argv[4], NULL, 0);
	}

	// unsigned long shell_len = PAGE_SIZE * 2;
	// unsigned long shell_len = end_vaddr - begin_vaddr + PAGE_SIZE;
	unsigned long shell_len = end_vaddr - begin_vaddr;
	char *sc_begin = create_shellcode(shell_len); 
	printf("[*] shell_len = %ld (%lx)\n", shell_len, shell_len);
	unsigned long **arr = malloc(4 * shell_len / PAGE_SIZE);
	get_shell_pa((unsigned long)sc_begin, shell_len, arr);
	for (int i = 0; i < shell_len / PAGE_SIZE; i++)
		printf("# %d: %lx\n", i, *arr[i]);
	inject(arr, shell_len / PAGE_SIZE, pid, begin_vaddr, end_vaddr + PAGE_SIZE);
	// inject(arr, shell_len / PAGE_SIZE, pid, begin_vaddr, end_vaddr);
	munmap(sc_begin, shell_len);
    // (*(void(*)())sc_begin)();
	// while (getchar() != EOF) {}
	return 0;
}
