# 2026-09-04 — Processes & Threads

## Book (Modern Operating Systems, 5th ed. — Tanenbaum & Bos)

Local copy: `/home/ephak/research/books/mos-5th-tanenbaum.pdf` (1185pp)

- Finish whatever's left of the Processes & Threads chapter — process states,
  context switching, scheduling basics, thread models (kernel vs user-level).
- Stop reading the moment a concept makes you go "how does Linux actually do
  this" — don't finish the section first, go look immediately.

(Also on disk, for later: *Operating Systems Design and Implementation*
3rd ed. at `/home/ephak/research/books/osdi-3rd-tanenbaum.pdf`. Not for
tomorrow, but flagging it exists.)

## kernel-internals.org — read alongside the source, not instead of it

These pages exist specifically for what tomorrow is trying to do:
- `syscalls/syscall-entry/` and `syscalls/syscall-define/` — syscall entry
  and dispatch mechanics, directly relevant to tracing `getpid()`.
- `kernel/early-boot/` — narrative walkthrough of `start_kernel()`.
- `mm/fork/` and `sched/sched-fork/` — "what happens when you fork()" and
  the scheduler's side of it. Queued for the later process-creation session,
  not tomorrow, but worth knowing it's there.

## Real source, first pass (`/home/ephak/linuxsrc/linux`, tag v7.3)

Not diving into `task_struct`/`copy_process` yet — that struct is one of the
largest and most historically-accreted in the whole tree, a rough first
thing to open cold. Doing two smaller, more orienting reads instead:

1. **`init/main.c` → `start_kernel()`.** Read it top to bottom. It's close
   to a linear list of "now bring up memory, now the scheduler, now the
   timer, now mount root" — gives a map of how the kernel's pieces fit
   together before understanding any one piece deeply.
2. **Trace `getpid()` end to end**, since it's small enough to hold in your
   head: `kernel/sys.c:999` — `SYSCALL_DEFINE0(getpid)`. Follow it from the
   syscall entry to what it actually touches. This is the generalizable
   move — same thing you'd do chasing an unfamiliar function later.

`task_struct` (`sched.h:835`), `copy_process()` (`fork.c:2012`), and
`execve` (`fs/exec.c`) are queued for a later session once there's more
navigation muscle — see `PLAN.md`.

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
