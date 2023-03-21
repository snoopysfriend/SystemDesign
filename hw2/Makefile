obj-m = rootkit.o 
PWD := $(shell pwd)
EXTRA_CFLAGS = -Wall -g
#KDIR :=  ../../linux
CROSS := aarch64-linux-gnu- 

all:
	$(MAKE) ARCH=arm64 CROSS_COMPILE=$(CROSS) -C $(KDIR) M=$(PWD) modules
	aarch64-linux-gnu-gcc -Wall test.c -o test

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean
