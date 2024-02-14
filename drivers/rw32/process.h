#include <linux/kernel.h>

uintptr_t get_module_base(pid_t pid, char* name);
int  get_proc_pid_list(char* name);
int getKallsymsLookupName(void);
