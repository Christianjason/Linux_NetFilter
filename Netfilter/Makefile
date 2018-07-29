#将hello.o编译成内核模块。obj-y 编译进内核 obj-n 不编译
obj-m := hellonetfilter.o

#指定交叉编译工具
CROSS_COMPILE =

#编译器使用gcc
CC = gcc

#指定内核源码位置/lib/modules/$(shell uname -r)/build or /usr/src/linux
#一些linux系统的源码在/usr/src/linux-headers-$(shell uname -r)
KERNELDIR ?= /lib/modules/$(shell uname -r)/build

#指定当前路径	
PWD := $(shell pwd)

all: modules

#	当make的目标为all时，-C $(KDIR) 指明跳转到内核源码目录下读取那里的Makefile；
#	M=$(PWD) 表明然后返回到当前目录继续读入、执行当前的Makefile。
modules:
	$(MAKE) -C $(KERNELDIR) M=$(PWD) modules

# make clean的时候删除编译产生的各种文件
clean:
	rm -rf *.o *~ core .depend *.symvers .*.cmd *.ko *.mod.c .tmp_versions $(TARGET)
