#ifndef __ROOTKIT_HW2_H
#define __ROOTKIT_HW2_H

#define MASQ_LEN	20
struct masq_proc {
	char new_name[MASQ_LEN];
	char orig_name[MASQ_LEN];
};

struct masq_proc_req {
	size_t len;
	struct masq_proc *list;
};
#define IOCTL_MOD_HOOK 101
#define IOCTL_MOD_HIDE 102 
#define IOCTL_MOD_MASQ 103

#endif /* __ROOTKIT_HW2_H */
