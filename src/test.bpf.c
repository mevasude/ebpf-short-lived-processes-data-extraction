
#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include <asm/unistd.h>
#include <bpf/bpf_helpers.h>
#include <string.h>
#include "helperfile.h"

#define CLONE_THREAD 0x00010000
#define BPF_PRINTK( format, ... ) \
    { char fmt[] = format; \
    bpf_trace_printk(fmt, sizeof(fmt), ##__VA_ARGS__ ); }

struct{
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256*1024);
} ringbuf SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u32));
    __uint(max_entries, MAX_PROC);
} event_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(key_size, sizeof(__u32));
	__uint(value_size, sizeof(event_exec_process_s));
	__uint(max_entries, MAX_PROC);
} exec_event_render SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(key_size, sizeof(__u64));
    __uint(value_size, sizeof(event_exec_process_s));
    __uint(max_entries, ARGS_HASH_SIZE);
} exec_events SEC(".maps");




__attribute__((always_inline))
int trace_execveimpl_enter(struct trace_event_raw_sys_enter *ctx, unsigned long syscall_id)
{

    uint64_t pid_tid = bpf_get_current_pid_tgid();
    uint64_t uid_gid = bpf_get_current_uid_gid();
    uint32_t cpu_id = bpf_get_smp_processor_id();

    int cmdline_index = 1;
    char **cmdline = NULL;
    long ret = 0;
    int i = 0;

    if ( syscall_id == __NR_execveat )
    {
        cmdline_index = 2;
    }

    event_exec_process_s *event = bpf_map_lookup_elem(&exec_event_render, &cpu_id);
    if (!event)
    {
        BPF_PRINTK("bpf_map_lookup_elem failed for exec_event_render map for sycall=%d, pid=%d," , syscall_id,  pid_tid >> 32);
        return 0;
    }
    
    event->kpath_cwd.dentries_number = 0;
    event->kpath_binary.dentries_number = 0;
    for (i = 0; i < MAX_CMDLINE_ARGS; i++)
    {
        event->cmdline[i][0] = '\0';
    }

    event->begin.event_type = event_type_exec_process;
    event->base.pid = pid_tid >> 32;
    event->base.pid2 = pid_tid >> 32;

    event->operation_time = bpf_ktime_get_ns();

    /*
    Extracting the process cmdline using the args in event structure
    */
    if ( BPF_CORE_READ_INTO(&cmdline, ctx, args[cmdline_index]) )
    {
        BPF_PRINTK("bpf_probe_read failed for cmdline from ctx args for sycall=%d, pid=%d\n", syscall_id, event->base.pid);
    }
    else
    {
        char *arg = NULL;
        for (i = 0; i < MAX_CMDLINE_ARGS; i++)
        {
            if ( bpf_probe_read_user(&arg, sizeof(arg), &cmdline[i]) < 0 )
            {
                BPF_PRINTK("bpf_probe_read_user failed to get arg[%d] for sycall=%d, pid=%d\n", i, syscall_id, event->base.pid);
                break;
            }

            if ( bpf_probe_read_user_str(event->cmdline[i], MAX_CMDLINE_ARGSIZE, arg) < 0)
            {
                BPF_PRINTK("bpf_probe_read_user_str failed for cmdline for sycall=%d, pid=%d, arg=%s\n", syscall_id, event->base.pid, arg);
                break;
            }
        }
    }
    
    if (bpf_map_update_elem(&exec_events, &pid_tid, event, BPF_ANY))
    {
        BPF_PRINTK("bpf_map_update_elem failed for exec_events map for sycall=%d, pid=%d," , syscall_id, event->base.pid);
        return 0;
    }

    // doing this in execve exit hook directly
    //int err = bpf_ringbuf_output(&ringbuf, event, sizeof(event_exec_process_s), 0);

    return 0;
}

SEC("tracepoint/syscalls/sys_enter_execve")
__attribute__((flatten))
int trace_execve_enter(struct trace_event_raw_sys_enter *ctx)
{
    BPF_PRINTK("Inside trace_execve_enter");
    return trace_execveimpl_enter(ctx, __NR_execve);
}



__attribute__((always_inline))
int get_dentry_kpath(struct dentry *dentry, struct dentry *mnt_dentry, event_kpath_s *event_kpath)
{
    struct dentry *d = dentry;
    struct dentry *mnt_d = mnt_dentry;
    struct dentry *d_parent;
    struct qstr dname;
    int err = 0;
    int i = 0;
    for (i = 0; i < KPATH_ENTRIES; ++i)
    {
        err = BPF_CORE_READ_INTO(&dname, d, d_name);
        if (err)
        {
            BPF_PRINTK("get_path: BPF_CORE_READ_INTO error for d_name, %d\n", err);
            break;
        }
        int read_size = bpf_probe_read_kernel_str(event_kpath->dentry[i], KPATH_ENTRY_SIZE, dname.name);
        if (read_size < 0)
        {
            BPF_PRINTK("get_path: bpf_probe_read_kernel error for name, %d\n", read_size);
            err = read_size;
            break;
        }
        event_kpath->dentry_sizes[i] = read_size - 1;
        err = BPF_CORE_READ_INTO(&d_parent, d, d_parent);
        if (err)
        {
            BPF_PRINTK("get_path: BPF_CORE_READ_INTO error for d_parent %d\n", err);
            break;
        }
        if (!d_parent || d == d_parent)
        {
            ++i;
            break;
        }
        d = d_parent;
    }

    d_parent = NULL;

    if(mnt_d != NULL)
    {
        for ( ; i < KPATH_ENTRIES; ++i)
        {
            err = BPF_CORE_READ_INTO(&dname, mnt_d, d_name);
            if (err)
            {
                BPF_PRINTK("get_path: BPF_CORE_READ_INTO error for d_name, %d\n", err);
                break;
            }
            int read_size = bpf_probe_read_kernel_str(event_kpath->dentry[i], KPATH_ENTRY_SIZE, dname.name);
            if (read_size < 0)
            {
                BPF_PRINTK("get_path: bpf_probe_read_kernel error for name, %d\n", read_size);
                err = read_size;
                break;
            }
            event_kpath->dentry_sizes[i] = read_size - 1;
            err = BPF_CORE_READ_INTO(&d_parent, mnt_d, d_parent);
            if (err)
            {
                BPF_PRINTK("get_path: BPF_CORE_READ_INTO error for d_parent %d\n", err);
                break;
            }
            if (!d_parent || mnt_d == d_parent)
            {
                ++i;
                break;
            }
            mnt_d = d_parent;
        }
    }
    event_kpath->dentries_number = i;
    return err;
}

__attribute__((always_inline))
int get_task_kpath(event_kpath_s *event_kpath, unsigned int kpath_type, struct task_struct *task)
{
    struct dentry *dentry = NULL;
    struct dentry *mnt_dentry = NULL;
    struct vfsmount *mnt_point = NULL;
    struct mount *mnt = NULL;
    int err = 0;

    if (kpath_type == kpath_type_process_path)
    {
        err = BPF_CORE_READ_INTO(&mnt_point, task, mm, exe_file, f_path.mnt);
        if (err)
        {
            BPF_PRINTK("get_task_kpath: BPF_CORE_READ_INTO error for mnt_point, %d\n", err);
            mnt_point = NULL;
        }

        err = BPF_CORE_READ_INTO(&dentry, task, mm, exe_file, f_path.dentry);
    }
    else
    {
        err = BPF_CORE_READ_INTO(&mnt_point, task, fs, pwd.mnt);
        if (err)
        {
            BPF_PRINTK("get_task_kpath: BPF_CORE_READ_INTO error for mnt_point, %d\n", err);
            mnt_point = NULL;
        }

        err = BPF_CORE_READ_INTO(&dentry, task, fs, pwd.dentry);
    }
    
    if (err)
    {
        BPF_PRINTK("get_task_kpath: unable to get dentry, error %d\n", err);
        return err;
    }

    if(mnt_point != NULL)
    {
        mnt = container_of(mnt_point, struct mount, mnt);

        err = BPF_CORE_READ_INTO(&mnt_dentry, mnt, mnt_mountpoint);
        if (err)
        {
            BPF_PRINTK("get_task_kpath: BPF_CORE_READ_INTO error for dentry, %d\n", err);
            mnt_dentry = NULL;
        }
    }

    return get_dentry_kpath(dentry, mnt_dentry, event_kpath);
}

__attribute__((always_inline))
int get_parent_pid(unsigned int *parent_pid, struct task_struct *task)
{
    struct task_struct *parent_task = NULL;
    unsigned int ppid;
    int err = 0;
    *parent_pid = 0;

    err = BPF_CORE_READ_INTO(&parent_task, task, real_parent);
    if ( err )
    {
        BPF_PRINTK("get_parent_pid: unable to get parent task, error %d\n", err);
    }
    else
    {
        err = BPF_CORE_READ_INTO(&ppid, parent_task, pid);
        if ( err )
        {
            BPF_PRINTK("get_parent_pid: unable to get parent pid from parent task, error %d\n", err);
        }
        else
        {
            *parent_pid = ppid;
        }
    }

    return err;
}


__attribute__((always_inline))
int trace_execveimpl_exit(struct trace_event_raw_sys_exit *ctx, unsigned long syscall_id)
{
    uint64_t pid_tid = bpf_get_current_pid_tgid();
    event_exec_process_s *event = NULL;

    // retrieve map storage for event
    event = bpf_map_lookup_elem(&exec_events, &pid_tid);
    if (!event)
    {
         BPF_PRINTK("bpf_map_lookup_elem failed for exec_events map in trace_execveimpl_exit for sycall=%d, pid=%d," , syscall_id,  pid_tid >> 32);
        return 0;
    }

    struct task_struct *task = (void *)bpf_get_current_task();

    /*
    Extracting the parent process pid using the parent task structure
    */
    if ( get_parent_pid(&event->parent_pid, task) )
    {
        BPF_PRINTK("unable to get parent pid for sycall=%d, pid=%d\n", syscall_id, event->base.pid);
    }

    /*
    Extracting the current working directory using the task structure
    */
    if ( get_task_kpath(&event->kpath_cwd, kpath_type_process_cwd, task) )
    {
        BPF_PRINTK("unable to get cwd for sycall=%d, pid=%d\n", syscall_id, event->base.pid);
    }
    
    /*
    Extracting the process path using the task structure
    */
    if ( get_task_kpath(&event->kpath_binary, kpath_type_process_path, task) )
    {
        BPF_PRINTK("unable to get process path for sycall=%d, pid=%d\n", syscall_id, event->base.pid);
    }

    /*
    Extracting process start time using the task struct
    */
   
    if (  BPF_CORE_READ_INTO(&event->base.start_time, task, start_boottime) )
    {
        BPF_PRINTK("unable to read bpf start time for sycall=%d, pid=%d\n", syscall_id, event->base.pid);
    }

    event->base.enriched = 1;

    int err = bpf_ringbuf_output(&ringbuf, event, sizeof(event_exec_process_s), 0);
    bpf_map_delete_elem(&exec_events, &pid_tid);

    return 0;
}


SEC("tracepoint/syscalls/sys_exit_execve")
__attribute__((flatten))
int trace_execve_exit(struct trace_event_raw_sys_exit *ctx)
{
    BPF_PRINTK("Inside trace_execve_exit");
    return trace_execveimpl_exit(ctx, __NR_execve);
}

struct tracepoint__task__task_newtask
{
    uint64_t    pad;
    __s32       pid;
    __s8        comm[16];
    uint64_t    clone_flags;
    __s16       oom_score_adj;
};

#define MAX_EVENT_SIZE (sizeof(event_exec_process_s))

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(key_size, sizeof(__u32));
	__uint(value_size, MAX_EVENT_SIZE);
	__uint(max_entries, MAX_PROC);
} event_storage_map SEC(".maps");

SEC("tracepoint/task/task_newtask") 
__attribute__((flatten))
int task_newtask(struct tracepoint__task__task_newtask *ctx)
{
    uint64_t pid_tid = bpf_get_current_pid_tgid();
    uint64_t uid_gid = bpf_get_current_uid_gid();
    uint32_t cpu_id = bpf_get_smp_processor_id();
    event_fork_process_s *event = NULL;

    if (ctx->clone_flags & CLONE_THREAD)
    {
        // thread creation - ignoring
        return 0;
    }

    // retrieve map storage for event
    event = bpf_map_lookup_elem(&event_storage_map, &cpu_id);
    if (!event)
    {
        return 0;
    }

    event->kpath_binary.dentries_number = 0;
    event->kpath_cwd.dentries_number = 0;

    event->base.pid = ctx->pid;
    event->base.pid2 = pid_tid >> 32;
    event->begin.event_type = event_type_fork_process;
    event->base.start_time = bpf_ktime_get_ns();

    struct task_struct *task = (void *)bpf_get_current_task();

    /*
    Extracting the current working directory using the task structure
    */
    if ( get_task_kpath(&event->kpath_cwd, kpath_type_process_cwd, task) )
    {
        BPF_PRINTK("unable to get cwd for __NR_fork, pid=%d\n", event->base.pid);
    }
    
    /*
    Extracting the process path using the task structure
    */
    if ( get_task_kpath(&event->kpath_binary, kpath_type_process_path, task) )
    {
        BPF_PRINTK("unable to get process path for __NR_fork, pid=%d\n", event->base.pid);
    }

    int err = bpf_ringbuf_output(&ringbuf, event, sizeof(event_fork_process_s), 0);
    return 0;
}

char _license[] SEC("license") = "GPL";
