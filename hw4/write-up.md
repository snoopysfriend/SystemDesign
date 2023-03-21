# HW4 write-up
宋哲寬 謝立峋
## How to run
```
$ mount -t seccompfs none /mnt
$ cd /mnt
$ echo "pid, len, sys1, ... sysn" > config
$ echo "begin" > begin # should see the dir of pid
```
## How we implement
### filesystem 
首先為了begin, config, log分別實作了自己的file_operations來支援不同功能的read以及write  
並在fill_super時用`tree_descr`存放並設定預設檔案的file_operations以及mode，並呼叫`simple_fill_super`來建立  
其餘一般inode的inode_operations都使用預設的`simple_lookup`或是`simplte_getattr`  
### seccomp filter
實作seccomp的第三種mode: SECCOMP_MODE_FILE  
修改 `struct seccomp`，新增允許的 syscall 列表，這會變成 `struct task_struct` 的一部分  
在執行到 `__secure_computing` 時，如果 mode 為 SECCOMP_MODE_FILE 則去檢查 syscall 是否在列表中  
若在列表中則回傳 SECCOMP_RET_ALLOW，否則回傳 SECCOMP_RET_KILL_THREAD 並終止 (參考 strict mode的作法)
## How we test
目前我們測過以下幾種情形：
1. Config 不合法 => 回傳 -EINVAL
2. 試圖 begin 已被 attach 過得 process => 回傳 -EINVAL
3. 新 attach 的 process 不會對過去的 filter 產生影響
4. 合法 config 及 begin 會在相應 `$PID/log` 中寫入 syscall, action
## Contribution
filesytem operation 宋哲寬
seccomp filter 謝立峋

