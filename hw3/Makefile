CC:=aarch64-linux-gnu-gcc
exe:=hw3-test hw3 hw3-sheep hw3-bonus

all: 
	aarch64-linux-gnu-gcc -Wall hw3-test.c -o hw3-test
	aarch64-linux-gnu-gcc -Wall hw3-sheep.c -o hw3-sheep
	aarch64-linux-gnu-gcc -Wall hw3.c -o hw3
	aarch64-linux-gnu-gcc -Wall -DBONUS hw3.c -o hw3-bonus


.PHONY: clean

clean:
	rm $(exe) 
