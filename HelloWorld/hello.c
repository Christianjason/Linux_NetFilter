#include <linux/kernel.h>
#include <linux/module.h>

int init_hello_module(void)
{
	printk("*************init_hello_module**************\n");
	printk("Hello World,init hwllo module\n");

	return 0;
}

void exit_hello_module(void)
{
	printk("*************exit_hello_module**************\n");
	printk("Bye World,exit hwllo module\n");
}


module_init(init_hello_module);
module_exit(exit_hello_module);
MODULE_LICENSE("GPL");