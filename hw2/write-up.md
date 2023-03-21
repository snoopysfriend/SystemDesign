# Hw2
-----------------------
r09944073 宋哲寬 謝立峋

## How to work
```
$ make KDIR=[linux dir] 
$ insmod rootkit.ko && mknod /dev/rootkit c 247 0 
$ ./ioctl 
```
## How it works
### hide
使用函式 `__list_deq` 將現在的`&THIS_MODULE->list`從 double-linked list移除，並將double-linked list的head存在memory裡，如果是要restore時，再使用`list_add_tail`將現在的list加回去linked list裡面
### masq
先使用`copy_from_user`將request從user-space copy過來，之後使用`for_each_process`去走訪每個process去看是否有process name相同的process並去修改comm來改名
### hook
參考資料：https://juejin.cn/post/6990646217399074853
1. 首先要把我們需要但 kernel 沒有 export 的 function 利用 `kallsyms_lookup_name()` 找出來。雖然在 HINT 中說要用 `kprobe` 拿 `kallsyms_lookup_name`，但其實 v5.4 還是有 export 的，所以我們就直接用 `kallsyms_lookup_name()` 就可以了。
2. 用 `update_mapping_prot` 更改 `.rodata` 的權限 (`__start_rodata` 到 `__init_begin`) 至可寫後就可以換成我們自己寫的 syscall，然後要把原本的 syscall 地址存下來用以恢復
3. 必須用 `struct pt_regs*` 來拿 input
4. `execve`: 拿第一個 register 就是 filename, 用 copy_from_user 之後 printk 就可以了。最後在 call 原本的 `sys_execve`
5. `reboot`: 直接 return 
6. 在 `module_exit` 的時候把 syscall table 恢復原狀

### bonus
另外實作了hook read來竊取使用者的key logging，原理是判斷system_read的fd是否為stdin並且fd在file descriptor table對應的
file屬於`/dev/*`，如果是則將read的結果存下來來做到key logging的效果
## How we test
make 之後會產生 `test`, 可將它搬到 vm 中執行。前兩個測試分別是 1. 單純 load/unload 2. 測試 hide 功能
第三個是測試 bonus 的 keylogger 功能，會需要實際用 keyboard 輸入並顯示得到的結果。可以去 dmesg 確認是否真的是由 printk 所產生的。
## How to test
我們將將hide, masq, hook分別對應了101, 102, 103在ioctl上的號碼，以下是call 對應的ioctl的api，當中masq裡面的req的type是`struct masq_proc_req`
```
#define IOCTL_MOD_HOOK 101
#define IOCTL_MOD_HIDE 102 
#define IOCTL_MOD_MASQ 103
ioctl(fd, IOCTL_MOD_MASQ, &req);
ioctl(fd, IOCTL_MOD_HIDE);
ioctl(fd, IOCTL_MOD_HOOK);
```
## Contribution
宋哲寬 hide & masq \
謝立峋 hook
