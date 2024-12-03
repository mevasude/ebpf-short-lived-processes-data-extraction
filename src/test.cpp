#include <array>
#include <chrono>
#include <fstream>
#include <filesystem>
#include <iostream>
#include <thread>
#include <vector>
#include <atomic>
#include <stdexcept>
#include <cstring>
#include <cstdlib>
#include <unistd.h>
#include <sys/resource.h>
#include <stdio.h>
#include <bpf/libbpf.h>
#include "helperfile.h"


// TO-DO: moving these to helperfile is throwing errors, need to update makefile probably
  std::string parse_kpath(event_kpath_s& kpath)
    {
      std::string result;
      for (int i = kpath.dentries_number - 1; i >= 0; --i)
      {
        result += kpath.dentry[i];
        if (result.back() != '/' && i > 0)
        {
          result += "/";
        }
      }
    return result;
    }

  std::string parse_cmdline(const char cmdline[MAX_CMDLINE_ARGS][MAX_CMDLINE_ARGSIZE])
  {
      std::string result;
      for (int i = 0; i < MAX_CMDLINE_ARGS && cmdline[i][0] != '\0'; i++)
      {
          result += cmdline[i];
          result += " ";
      }
      return result;
  }

  static int event_logger(void* ctx, void* data, size_t len) {
    //event_fork_process_s *event_process = static_cast<event_fork_process_s*>(data);
    event_exec_process_s *event_process = static_cast<event_exec_process_s*>(data);    
    // Construct command line string
    std::string cmdline;
    for (int i = 0; i < MAX_CMDLINE_ARGS && event_process->cmdline[i][0] != '\0'; ++i) {
      cmdline += event_process->cmdline[i];
      if (i < MAX_CMDLINE_ARGS - 1 && event_process->cmdline[i + 1][0] != '\0') {
        cmdline += " ";
      }
    }
    // Parse paths
    std::string process_cmdline = parse_cmdline(event_process->cmdline);
    std::string process_cwd = parse_kpath(event_process->kpath_cwd);
    std::string process_path = parse_kpath(event_process->kpath_binary);

    printf(
        "Event Log - Start Time: %lu, PID: %d, PPID: %d, Process Path: %s, Cmd: %s, CWD: %s\n",
        event_process->base.start_time,
        event_process->base.pid,
        event_process->parent_pid,
        process_path.c_str(),
        process_cmdline.c_str(),
        process_cwd.c_str()
    );

    return 0;
  }
   



int main(int argc, char **argv) {
  
  const char* mapname = "ringbuf";  
  int err ; 
  struct    bpf_object  *_bpf_obj = NULL; 

  // Refernce and open the ebpf object file :bpf_object__open_file
  _bpf_obj = bpf_object__open("test.bpf.o");

  if (!_bpf_obj){
    printf("unable to open the object"); 
    return -1;
  }

  if ( bpf_object__load(_bpf_obj))
  {
      printf("unable to load the object");
      return -1;     
  }

  int rbFd = bpf_object__find_map_fd_by_name(_bpf_obj, mapname);
  if (rbFd < 0) {
    printf("Failed to find map '%s': %s\n", mapname, strerror(-rbFd));
    return 1;
  }

  struct ring_buffer* ringBuffer = ring_buffer__new(rbFd, event_logger, NULL, NULL);
  if(!ringBuffer) {
    puts("Failed to creare ring buffer");
    return 1;
  }

  struct bpf_program *prog_execve_enter = bpf_object__find_program_by_name(_bpf_obj , "trace_execve_enter") ;
  if ( prog_execve_enter == NULL){
    printf("unable to find the prog_execve_enter program"); 
    return -1; 
  }

  struct bpf_program *prog_execve_exit = bpf_object__find_program_by_name(_bpf_obj , "trace_execve_exit") ;
  if ( prog_execve_exit == NULL){
    printf("unable to find the prog_execve_exit program"); 
    return -1; 
  }

  struct bpf_program *prog_task_newtask = bpf_object__find_program_by_name(_bpf_obj , "task_newtask") ;
  if ( prog_task_newtask == NULL){
    printf("unable to find the prog_task_newtask program"); 
    return -1; 
  }

  bpf_program__attach(prog_execve_enter);
  bpf_program__attach(prog_execve_exit);
  bpf_program__attach(prog_task_newtask);

  while (true)
  {
    ring_buffer__consume(ringBuffer);
  }
  return 0;
}


// // Refernce and open the ebpf object file :bpf_object__open_file
//   _bpf_obj = bpf_object__open_file("test.bpf.o", NULL);

//   if (libbpf_get_error(_bpf_obj)){
//     printf("unable to open the object"); 
//     return -1;
//   }

//   // refernce the programs that you want to attach2 : find_program_by_title
//   struct bpf_program *prog = find_program_by_title(_bpf_obj , "trace_execve_enter") ;
//   if ( prog == NULL){
//     printf("unable to find the program"); 
//     return -1; 
//   }


//    // refernce the programs that you want to attach2 : find_program_by_title
//   struct bpf_program *prog2 = find_program_by_title(_bpf_obj , "trace_execve_exit") ;
//   if ( prog2 == NULL){
//     printf("unable to find the program"); 
//     return -1; 
//   }

//   //type of the proram : bpf_program__set_type
//   bpf_program__set_type(prog, BPF_PROG_TYPE_TRACEPOINT);

//   //type of the proram : bpf_program__set_type
//   bpf_program__set_type(prog2, BPF_PROG_TYPE_TRACEPOINT);

//   //load the object : bpf_object__load
//   if ( bpf_object__load(_bpf_obj))
//   {
//       printf("unable to load the object");
//       return -1;     
//   }

  
//   bpf_program__attach_tracepoint(prog , "syscalls" , "sys_enter_execve" );
//   bpf_program__attach_tracepoint(prog2 , "syscalls" , "sys_exit_execve" );



//   int rbFd = bpf_object__find_map_fd_by_name(_bpf_obj, mapname);
//   if (rbFd < 0) {
//     printf("Failed to find map '%s': %s\n", mapname, strerror(-rbFd));
//     return 1;
// }
//   printf("rbFd = %d\n", rbFd);
//   struct ring_buffer* ringBuffer = ring_buffer__new(rbFd, event_logger, NULL, NULL);
//   if(!ringBuffer) {
//     puts("Failed to creare ring buffer");
//     return 1;
//   }


 





//   while (true)
//   {
//     ring_buffer__consume(ringBuffer);
//     // keep the object file running
//   }
//   return 0;