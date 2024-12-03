#define KPATH_ENTRIES       (16)
#define KPATH_ENTRY_SIZE    (256)
#define MAX_CMDLINE_ARGSIZE (4096)
#define MAX_CMDLINE_ARGS    (16)
#define MAX_PROC 512
#define ARGS_HASH_SIZE 5120

enum event_type
{
    event_type_none = 0,
    event_type_fork_process = 1,
    event_type_exec_process = 2    
};

typedef struct e_begin_rec
{
    unsigned long int  code_bytes_start; // Always 0xdeadbeef = 3735928559
    unsigned int       version;
    unsigned int       event_type;
    unsigned int       size;
} event_begin_s;

typedef struct e_kpath
{
    char dentry[KPATH_ENTRIES][KPATH_ENTRY_SIZE];
    unsigned long dentry_sizes[KPATH_ENTRIES];
    unsigned int dentries_number;
} event_kpath_s;



typedef struct e_end_rec
{
    unsigned long int  code_bytes_end; // Always 0xdeadbeef = 3735928559
} event_end_s;


typedef struct e_base_rec
{
    unsigned long      timestamp_enter_ns;
    unsigned long      timestamp_exit_ns;
    unsigned int       status;
    unsigned long      syscall_id;
    unsigned long      a[8]; // Should only be 6 but this helps with verifier
    unsigned int       pid;
    unsigned int       tid;
    uint64_t           start_time;
    unsigned int       pid2; // for fork/exec/exit events
    long int           return_code;
    unsigned int       uid;
    unsigned int       gid;
    unsigned int       euid;
    unsigned int       egid;
    unsigned char      enriched;
    unsigned int       pid_ns_id;
} event_base_s;

typedef struct e_exec_process_rec
{
    event_begin_s       begin;
    event_base_s        base;
    unsigned int        parent_pid;
    char                cmdline[MAX_CMDLINE_ARGS][MAX_CMDLINE_ARGSIZE]; // process commandline
    event_kpath_s       kpath_binary; // process path
    event_kpath_s       kpath_cwd; // current working directory
    uint64_t            operation_time;
    event_end_s         end;
} event_exec_process_s;


typedef struct e_fork_process_rec
{
    event_begin_s       begin;
    event_base_s        base;
    event_kpath_s       kpath_binary; // process path
    event_kpath_s       kpath_cwd; // current working directory
    event_end_s         end;
} event_fork_process_s;

enum event_kpath_type
{
    kpath_type_process_path = 0,
    kpath_type_process_cwd = 1
};