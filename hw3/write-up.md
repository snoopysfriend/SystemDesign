# Hw3 write-up
-----------------
宋哲寬 謝立峋
## How to build
```
$ patch < kernel.patch    # apply patch in linux kernel
$ make ARCH=arm64 CROSS_COMPILE=aarch64-linux-gnu- -j4
$ make                    # make the test program
```
## How to run
```
$ ./hw3-sheep             # this would run the sheep program
$ ./hw3-test -i <pid> <begin_addr> <end_addr> # this would print out 
$ ./hw3 -i <pid>          # this would inject 
```
## System call
對於要remap的target addr首先會去walk page table去尋找其pte_table(pmd entry), 然後將pte_table's pfn(page frame number)
利用`remap_pfn_range` 將他map到user space上面，而flatten page table會依序的存放remapped的pte_table的user space address

若要測試可以執行 `$ ./hw3-test -i <pid> <begin_addr> <end_addr> # this would print out`
當中addr都是使用16進位，會將`begin addr`以4k的間隔印出來對應的physical address，若對應的address發生page fualt則會印出0
## Code injection

首先會去 `/proc/<pid>/maps` 底下拿 text 段的範圍
生成一樣大小的 shellcode pages
接著分別呼叫 target 與自己的 expose_pte
最後將 target text 段的 page table 與自己 shellcode pages 互換

若要重現，可以開啟 tmux，執行

```
$ ./hw3-sheep
```

接著在另一個 tmux 頁面

```
$ ps aux | grep hw3-sheep
$ ./hw3 -i <pid-of-hw3-sheep>
```

可能會出現一些警告，回到 sheep 頁面會發現正在執行 sh

### Bonus

會生成 `/tmp/pwned`，內容是 "You're hacked!"

選用 sshd 作為目標，因為我們只取代 text 段，所以最後要執行 ssh 讓他跳出 lib 才會觸發

```
$ ps aux | grep sshd
$ ./hw3-bonus -i <pid-of-sshd>
$ ssh localhost
$ cat /tmp/pwned
You're hacked!
```

## Contribution 
宋哲寬 expose_pte
謝立峋 code injection
