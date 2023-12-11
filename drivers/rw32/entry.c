#include <linux/module.h>
#include <linux/tty.h>
#include <linux/random.h>
#include "comm.h"
#include "memory.h"
#include "process.h"
#define DEVICE_NAME "wlan2"

static dev_t dev_num;
static struct cdev my_cdev;
static struct class *my_class; // 定义设备类指针
static bool hide=false;
//static char DEVICE_NAME[5];

int dispatch_open(struct inode *node, struct file *file)
{
     if(hide==false)
    {
        hide=true;
        device_destroy(my_class, dev_num);
	class_destroy(my_class);
    }
    return 0;
}

int dispatch_close(struct inode *node, struct file *file)
{
    if(hide==true)
    {	
	hide=false;
        my_class = class_create(THIS_MODULE, DEVICE_NAME);
        device_create(my_class, NULL, dev_num, NULL, DEVICE_NAME);

    }
    return 0;
}

long dispatch_ioctl(struct file* const file, unsigned int const cmd, unsigned long const arg)
{
    static COPY_MEMORY cm;
    static MODULE_BASE mb;
    //static char key[0x100] = {0};
    static char name[0x100] = {0};
    //static bool is_verified = false;
    switch (cmd) {
        case OP_READ_MEM:
            {
                if (copy_from_user(&cm, (void __user*)arg, sizeof(cm)) != 0) {
                    return -1;
                }
                if (read_process_memory(cm.pid, cm.addr, cm.buffer, cm.size) == false) {
                    return -1;
                }
            }
            break;
        case OP_WRITE_MEM:
            {
                if (copy_from_user(&cm, (void __user*)arg, sizeof(cm)) != 0) {
                    return -1;
                }
                if (write_process_memory(cm.pid, cm.addr, cm.buffer, cm.size) == false) {
                    return -1;
                }
            }
            break;
        case OP_MODULE_BASE:
            {
                if (copy_from_user(&mb, (void __user*)arg, sizeof(mb)) != 0 
                ||  copy_from_user(name, (void __user*)mb.name, sizeof(name)-1) !=0) {
                    return -1;
                }
                mb.base = get_module_base(mb.pid, name);
                if (copy_to_user((void __user*)arg, &mb, sizeof(mb)) !=0) {
                    return -1;
                }
            }
	  break;
        case SB:
            {
                if (copy_from_user(&cm, (void __user*)arg, sizeof(cm)) != 0) {
                    return -1;
                }
                cm.pid=666;
                return 2;
            }
            break;
        default:
            break;
    }
    return 0;
}

struct file_operations dispatch_functions = {
    .owner   = THIS_MODULE,
    .open    = dispatch_open,
    .release = dispatch_close,
    .unlocked_ioctl = dispatch_ioctl,
};

int __init driver_entry(void) {
    printk("[+] driver_entry");
    int ret;

    // 动态分配主设备号和次设备号
    ret = alloc_chrdev_region(&dev_num, 0, 1, DEVICE_NAME);
    if (ret < 0) {
        printk(KERN_ALERT "Unable to allocate device number\n");
        return ret;
    }

    // 初始化字符设备
    cdev_init(&my_cdev, &dispatch_functions);
    my_cdev.owner = THIS_MODULE;

    // 添加字符设备到系统
    ret = cdev_add(&my_cdev, dev_num, 1);
    if (ret < 0) {
        printk(KERN_ALERT "Unable to add character device\n");
        unregister_chrdev_region(dev_num, 1);
        return ret;
    }

    printk(KERN_INFO "Character device registration with main device number %d\n", MAJOR(dev_num));
    my_class = class_create(THIS_MODULE, DEVICE_NAME);
if (IS_ERR(device_create(my_class, NULL, dev_num, NULL, DEVICE_NAME))) {
        printk(KERN_ALERT "Unable to create device node\n");
        cdev_del(&my_cdev);
        unregister_chrdev_region(dev_num, 1);
        return -1;
    }

    printk(KERN_INFO "Device node created successfully\n");
    list_del_init(&__this_module.list);
    kobject_del(&THIS_MODULE->mkobj.kobj);
    return 0;
}

void __exit driver_unload(void) {
    printk("[+] driver_unload");

   // 从系统中移除字符设备
    cdev_del(&my_cdev);

    // 释放分配的设备号
    unregister_chrdev_region(dev_num, 1);
    printk(KERN_INFO "字符设备注销\n");
}

module_init(driver_entry);
module_exit(driver_unload);

MODULE_DESCRIPTION("Linux Kernel.");
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Tao");
