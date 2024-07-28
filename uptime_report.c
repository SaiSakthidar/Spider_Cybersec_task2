#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/ktime.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Sai");
MODULE_DESCRIPTION("Linux kernel module to report the system uptime");

static int __init uptime_report_init(void)
{
    printk(KERN_INFO "uptime_report: Module loaded.\n");
    printk(KERN_INFO "uptime_report: System uptime is %lld seconds.\n", ktime_get_real_seconds());
    return 0;
}

static void __exit uptime_report_exit(void)
{
    printk(KERN_INFO "uptime_report: Module unloaded.\n");
}

module_init(uptime_report_init);
module_exit(uptime_report_exit);
