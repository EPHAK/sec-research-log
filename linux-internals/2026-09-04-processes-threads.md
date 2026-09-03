# 2026-09-04 — Processes & Threads

## Book (Modern Operating Systems)

- Finish whatever's left of the Processes & Threads chapter — process states,
  context switching, scheduling basics, thread models (kernel vs user-level).
- Stop reading the moment a concept makes you go "how does Linux actually do
  this" — don't finish the section first, go look immediately.

## Real source to map it to (`/home/ephak/linuxsrc/linux`, tag v7.3)

| Concept | Where |
|---|---|
| What a process/thread actually is | `include/linux/sched.h:835` — `struct task_struct` |
| Creating a process/thread | `kernel/fork.c:2012` — `copy_process()` |
| The `fork()`/`clone()`/`vfork()` syscalls | `kernel/fork.c` — `kernel_clone()` at `:2712`, search `SYSCALL_DEFINE0(fork)` |
| Replacing the process image | `fs/exec.c` — `SYSCALL_DEFINE3(execve, ...)` |
| Scheduler | `kernel/sched/core.c`, `kernel/sched/fair.c` (CFS/EEVDF) |

Don't try to read these top to bottom. Open `task_struct` first, skim the
fields, notice which ones map to concepts the book just described (pid,
state, mm, files, thread info) and which ones are a surprise.

## Hands-on (do these, don't just read)

```
ps -eLf                     # processes vs threads (LWP column)
cat /proc/self/status       # a live task_struct's userspace view
cat /proc/self/status | grep Threads
strace -f -e trace=clone,fork,vfork,execve ./some_program
```

Write a 5-line C program that calls `fork()` and one that calls
`pthread_create()`, run both under `strace -f`, compare what syscalls each
one actually makes.

## Notes

_(fill in during/after — raw is fine)_
