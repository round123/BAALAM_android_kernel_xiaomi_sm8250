#include "process.h"

#include <linux/sched/mm.h> //4.19
#include <linux/module.h>
#include <linux/tty.h>
#include <linux/mm.h>
#include <linux/version.h>
#include "linux/kallsyms.h"
#include <linux/slab.h>
#include <linux/sched/signal.h>
#define PARM_LENTH 256
#define ARC_PATH_MAX 256

extern struct mm_struct *get_task_mm(struct task_struct *task);

#if(LINUX_VERSION_CODE >= KERNEL_VERSION(5, 4, 61))
extern void mmput(struct mm_struct *);
#endif
static unsigned long (*kallsyms_lookup_name_fn)(const char *name);
static int (*get_cmdline_fn)(struct task_struct *task, char *buffer, int buflen);
unsigned long kaddr_lookup_name(const char *fname_raw)
{
	int i;
	unsigned long kaddr;
	char *fname_lookup, *fname;

	fname_lookup = kzalloc(NAME_MAX, GFP_KERNEL);
	if (!fname_lookup)
		return 0;

	fname = kzalloc(strlen(fname_raw) + 4, GFP_KERNEL);
	if (!fname)
		return 0;

	/*
   * We have to add "+0x0" to the end of our function name
   * because that's the format that sprint_symbol() returns
   * to us. If we don't do this, then our search can stop
   * prematurely and give us the wrong function address!
   */
	strcpy(fname, fname_raw);
	strcat(fname, "+0x0");

	/*获取内核代码段基地址*/
	kaddr = (unsigned long)&sprint_symbol;
	kaddr &= 0xffffffffff000000;

	/*内核符号不会超过0x100000*16的大小，所以按4字节偏移，挨个找*/
	for (i = 0x0; i < 0x400000; i++) {
		/*寻找地址对应的符号名称*/
		sprint_symbol(fname_lookup, kaddr);
		/*对比寻找的符号名字*/
		if (strncmp(fname_lookup, fname, strlen(fname)) == 0) {
			/*找到了就返回地址*/
			kfree(fname_lookup);
			kfree(fname);
			return kaddr;
		}
		/*偏移4字节*/
		kaddr += 0x04;
	}
	/*没找到地址就返回0*/
	kfree(fname_lookup);
	kfree(fname);
	return 0;
}

static int getKallsymsLookupName(void)
{
	kallsyms_lookup_name_fn =
		(void *)kaddr_lookup_name("kallsyms_lookup_name");
	if (!kallsyms_lookup_name_fn) {
		printk("get kallsyms_lookup_name fail \n");
		return -1;
	}
	return 0;
}

/* 将获取的buffer中的 ‘\0’替换成空格 */
static void deal_raw_cmdline(char *buffer, unsigned int length)
{
        int i = 0;
        for (i = 0; i < length; i ++) {
                if (buffer[i] == '\0') {
                        buffer[i] = ' ';
                }
        }
}
int  get_proc_pid_list(char* name)
{
        int ret = 0;
        int pid=0;
        struct task_struct *tsk = NULL;
        char buffer[PARM_LENTH] = {0};
        /* 这里无法用kallsyms_lookup_name获取函数get_cmdline的地址 */
        get_cmdline_fn = (int (*)(struct task_struct *, char *, int))
                        kallsyms_lookup_name_fn("get_cmdline");
        if (get_cmdline_fn == NULL) {
                printk("Get func get_cmdline address failed\n");
        }


        rcu_read_lock();
        for_each_process(tsk) {
                printk("pid -> %d comm -> %s\n", tsk->pid, tsk->comm);
                if (tsk->mm == NULL) {
                        continue;
                }

                memset(buffer, 0, sizeof(buffer));
                ret = get_cmdline_fn(tsk, buffer, sizeof(buffer));
                if (ret < 0) {
                        continue;
                }
                if (strcmp(name,buffer))
                {
                    pid=tsk->pid;
                }
                
               
        }
        rcu_read_unlock();

        return pid;
}


uintptr_t get_module_base(pid_t pid, char* name) 
{
    struct pid* pid_struct;
    struct task_struct* task;
    struct mm_struct* mm;
    struct vm_area_struct *vma;

    pid_struct = find_get_pid(pid);
    if (!pid_struct) {
        return false;
    }
    task = get_pid_task(pid_struct, PIDTYPE_PID);
    if (!task) {
        return false;
    }
    mm = get_task_mm(task);
    if (!mm) {
        return false;
    }
    mmput(mm);

    for (vma = mm->mmap; vma; vma = vma->vm_next) {
        char buf[ARC_PATH_MAX];
        char *path_nm = "";

        if (vma->vm_file) {
            path_nm = file_path(vma->vm_file, buf, ARC_PATH_MAX-1);
            if (!strcmp(kbasename(path_nm), name)) {
                return vma->vm_start;
            }
        }
    }
    return 0;
}
 
